/*
 * A Simple Filesystem for the Linux Kernel.
 *
 * Initial author: Sankar P <sankar.curiosity@gmail.com>
 * License: Creative Commons Zero License - http://creativecommons.org/publicdomain/zero/1.0/
 *
 * TODO: we need to split it into smaller files
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/buffer_head.h>
#include <linux/slab.h>
#include <linux/random.h>
#include <linux/version.h>
#include <linux/mpage.h>
#include <linux/uio.h>
#include <linux/iomap.h>
#include <linux/quotaops.h>
#include <linux/xattr.h>
#include <linux/posix_acl.h>

#include "super.h"
#define f_dentry f_path.dentry

/* A super block lock that must be used for any critical section operation on the sb,
 * such as: updating the free_blocks, inodes_count etc. */
static DEFINE_MUTEX(simplefs_sb_lock);
static DEFINE_MUTEX(simplefs_inodes_mgmt_lock);

/* FIXME: This can be moved to an in-memory structure of the simplefs_inode.
 * Because of the global nature of this lock, we cannot create
 * new children (without locking) in two different dirs at a time.
 * They will get sequentially created. If we move the lock
 * to a directory-specific way (by moving it inside inode), the
 * insertion of two children in two different directories can be
 * done in parallel */
static DEFINE_MUTEX(simplefs_directory_children_update_lock);

static struct kmem_cache *sfs_inode_cachep;

void simplefs_sb_sync(struct super_block *vsb)
{
	struct buffer_head *bh;
	struct simplefs_super_block *sb = SIMPLEFS_SB(vsb);

	bh = sb_bread(vsb, SIMPLEFS_SUPERBLOCK_BLOCK_NUMBER);
	BUG_ON(!bh);

	bh->b_data = (char *)sb;
	mark_buffer_dirty(bh);
	sync_dirty_buffer(bh);
	brelse(bh);
}

struct simplefs_inode *simplefs_inode_search(struct super_block *vsb,
		struct simplefs_inode *start,
		struct simplefs_inode *search)
{
	struct simplefs_super_block *sb = SIMPLEFS_SB(vsb);

	start += (search->inode_no - 1);
	if(((1<<(search->inode_no - 1)) & sb->inodes_table) && start->inode_no == search->inode_no)
	{
		return start;
	}

	return NULL;
}

void simplefs_inode_del(struct super_block *vsb, struct simplefs_inode *inode)
{
	struct simplefs_super_block *sb = SIMPLEFS_SB(vsb);

	if (mutex_lock_interruptible(&simplefs_inodes_mgmt_lock)) {
		sfs_trace("Failed to acquire mutex lock\n");
		return;
	}

	if (mutex_lock_interruptible(&simplefs_sb_lock)) {
		sfs_trace("Failed to acquire mutex lock\n");
		return;
	}

	sb->inodes_count--;
	sb->inodes_table &= ~(1<<(inode->inode_no - 1));

	simplefs_sb_sync(vsb);

	mutex_unlock(&simplefs_sb_lock);
	mutex_unlock(&simplefs_inodes_mgmt_lock);
}

void simplefs_inode_add(struct super_block *vsb, struct simplefs_inode *inode)
{
	struct simplefs_super_block *sb = SIMPLEFS_SB(vsb);
	struct buffer_head *bh;
	struct simplefs_inode *inode_iterator;

	if (mutex_lock_interruptible(&simplefs_inodes_mgmt_lock)) {
		sfs_trace("Failed to acquire mutex lock\n");
		return;
	}

	bh = sb_bread(vsb, SIMPLEFS_INODESTORE_BLOCK_NUMBER);
	BUG_ON(!bh);

	inode_iterator = (struct simplefs_inode *)bh->b_data;

	if (mutex_lock_interruptible(&simplefs_sb_lock)) {
		sfs_trace("Failed to acquire mutex lock\n");
		return;
	}

	/* Append the new inode in the inode store by inode id */
	inode_iterator += (inode->inode_no - 1);

	memcpy(inode_iterator, inode, sizeof(struct simplefs_inode));
	sb->inodes_count++;
	sb->inodes_table |= (1<<(inode->inode_no - 1));
	printk(KERN_INFO "inode_no=%llu, inodes_table=%llx, inodes_count=%llu\n", inode->inode_no,
			sb->inodes_table, sb->inodes_count);
	mark_buffer_dirty(bh);
	simplefs_sb_sync(vsb);
	brelse(bh);

	mutex_unlock(&simplefs_sb_lock);
	mutex_unlock(&simplefs_inodes_mgmt_lock);
}

int simplefs_sb_release_a_datablock(struct super_block *vsb, uint64_t datablock_no)
{
	struct simplefs_super_block *sb = SIMPLEFS_SB(vsb);
	int ret = 0;

	if (mutex_lock_interruptible(&simplefs_sb_lock)) {
		sfs_trace("Failed to acquire mutex lock\n");
		ret = -EINTR;
		goto end;
	}

	/* Set the identified block from the free list */
	sb->free_blocks |= (1 << datablock_no);

	simplefs_sb_sync(vsb);

end:
	mutex_unlock(&simplefs_sb_lock);
	return ret;
}

static void simplefs_clear_datablock(struct super_block *vsb, uint64_t datablock_no)
{
	struct buffer_head *bh;
	char *data;
	bh = sb_bread(vsb, datablock_no);
	BUG_ON(!bh);

	data = (char *)bh->b_data;
	memset(data, 0, SIMPLEFS_DEFAULT_BLOCK_SIZE);

	mark_buffer_dirty(bh);
	sync_dirty_buffer(bh);
	brelse(bh);
}

/* This function returns a blocknumber which is free.
 * The block will be removed from the freeblock list.
 *
 * In an ideal, production-ready filesystem, we will not be dealing with blocks,
 * and instead we will be using extents
 *
 * If for some reason, the file creation/deletion failed, the block number
 * will still be marked as non-free. You need fsck to fix this.*/
int simplefs_sb_get_a_freeblock(struct super_block *vsb, uint64_t * out, int isclear)
{
	struct simplefs_super_block *sb = SIMPLEFS_SB(vsb);
	int i;
	int ret = 0;

	if (mutex_lock_interruptible(&simplefs_sb_lock)) {
		sfs_trace("Failed to acquire mutex lock\n");
		ret = -EINTR;
		goto end;
	}

	/* Loop until we find a free block. We start the loop from 3,
	 * as all prior blocks will always be in use */
	for (i = 3; i < SIMPLEFS_MAX_FILESYSTEM_OBJECTS_SUPPORTED; i++) {
		if (sb->free_blocks & (1 << i)) {
			break;
		}
	}

	if (unlikely(i == SIMPLEFS_MAX_FILESYSTEM_OBJECTS_SUPPORTED)) {
		printk(KERN_ERR "No more free blocks available");
		ret = -ENOSPC;
		goto end;
	}

	*out = i;
	if(isclear)
		simplefs_clear_datablock(vsb, i);

	/* Remove the identified block from the free list */
	sb->free_blocks &= ~(1 << i);

	simplefs_sb_sync(vsb);

end:
	mutex_unlock(&simplefs_sb_lock);
	return ret;
}

static int simplefs_sb_get_objects_count(struct super_block *vsb,
					 uint64_t * out, uint64_t *next_inode_no)
{
	uint64_t i;
	struct simplefs_super_block *sb = SIMPLEFS_SB(vsb);

	if (mutex_lock_interruptible(&simplefs_inodes_mgmt_lock)) {
		sfs_trace("Failed to acquire mutex lock\n");
		return -EINTR;
	}
	*out = sb->inodes_count;
	*next_inode_no = SIMPLEFS_MAX_FILESYSTEM_OBJECTS_SUPPORTED + 1;
	//skip 1 root inode
	for(i=1; i<SIMPLEFS_MAX_FILESYSTEM_OBJECTS_SUPPORTED; i++)
	{
		if(!((1<<i) & sb->inodes_table))
		{
			*next_inode_no = i + 1;
			break;
		}
	}
	mutex_unlock(&simplefs_inodes_mgmt_lock);

	return 0;
}

static inline void simplefs_put_page(struct page *page)
{
	kunmap(page);
	put_page(page);
}

static struct page * simplefs_get_page(struct inode *dir, unsigned long n)
{
	struct address_space *mapping = dir->i_mapping;
	struct page *page = read_mapping_page(mapping, n, NULL);
	if (!IS_ERR(page)) {
		kmap(page);
		if (unlikely(!PageChecked(page))) {
			if (PageError(page))
				goto fail;
		}
	}
	return page;

fail:
	simplefs_put_page(page);
	return ERR_PTR(-EIO);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 11, 0)
static int simplefs_iterate(struct file *filp, struct dir_context *ctx)
#else
static int simplefs_readdir(struct file *filp, void *dirent, filldir_t filldir)
#endif
{
	loff_t pos;
	struct inode *inode;
	struct super_block *sb;
	struct simplefs_inode *sfs_inode;
	struct simplefs_dir_record *record;
	char *kaddr;
	char *endaddr;
	struct page *page;
	int i;

	printk(KERN_DEBUG "simplefs_iterate %s\n", filp->f_dentry->d_name.name);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 11, 0)
	pos = ctx->pos;
#else
	pos = filp->f_pos;
#endif
	inode = filp->f_dentry->d_inode;
	sb = inode->i_sb;

	if (pos) {
		/* FIXME: We use a hack of reading pos to figure if we have filled in all data.
		 * We should probably fix this to work in a cursor based model and
		 * use the tokens correctly to not fill too many data in each cursor based call */
		return 0;
	}

	sfs_inode = SIMPLEFS_INODE(inode);

	if (unlikely(!S_ISDIR(sfs_inode->mode))) {
		printk(KERN_ERR
		       "inode [%llu][%lu] for fs object [%s] not a directory\n",
		       sfs_inode->inode_no, inode->i_ino,
		       filp->f_dentry->d_name.name);
		return -ENOTDIR;
	}

	page = simplefs_get_page(inode, 0);

	if (IS_ERR(page)) {
		printk(KERN_ERR "bad page in #%lu", inode->i_ino);
		ctx->pos += PAGE_SIZE;
		return PTR_ERR(page);
	}

	kaddr = page_address(page);
	endaddr = kaddr + inode->i_size;
	record = (struct simplefs_dir_record *)kaddr;
	for (i = 0; i < sfs_inode->dir_children_count && (char*)record < endaddr;)
	{
		if(record->inode_no != 0)
		{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 11, 0)
			dir_emit(ctx, record->filename, SIMPLEFS_FILENAME_MAXLEN,
					record->inode_no, DT_UNKNOWN);
			ctx->pos += sizeof(struct simplefs_dir_record);
#else
			filldir(dirent, record->filename, SIMPLEFS_FILENAME_MAXLEN, pos,
					record->inode_no, DT_UNKNOWN);
			filp->f_pos += sizeof(struct simplefs_dir_record);
#endif
			pos += sizeof(struct simplefs_dir_record);
			i++;
		}
		record++;
	}
	simplefs_put_page(page);

	return 0;
}

/* This functions returns a simplefs_inode with the given inode_no
 * from the inode store, if it exists. */
struct simplefs_inode *simplefs_get_inode(struct super_block *sb,
					  uint64_t inode_no)
{
	struct simplefs_super_block *sfs_sb = SIMPLEFS_SB(sb);
	struct simplefs_inode *sfs_inode = NULL;
	struct simplefs_inode *inode_buffer = NULL;

	struct buffer_head *bh;

	/* The inode store can be read once and kept in memory permanently while mounting.
	 * But such a model will not be scalable in a filesystem with
	 * millions or billions of files (inodes) */
	bh = sb_bread(sb, SIMPLEFS_INODESTORE_BLOCK_NUMBER);
	BUG_ON(!bh);

	sfs_inode = (struct simplefs_inode *)bh->b_data;

#if 0
	if (mutex_lock_interruptible(&simplefs_inodes_mgmt_lock)) {
		printk(KERN_ERR "Failed to acquire mutex lock %s +%d\n",
		       __FILE__, __LINE__);
		return NULL;
	}
#endif

	sfs_inode += (inode_no - 1);
	if(((1<<(inode_no - 1)) & sfs_sb->inodes_table) && sfs_inode->inode_no == inode_no)
	{
		inode_buffer = kmem_cache_alloc(sfs_inode_cachep, GFP_KERNEL);
		memcpy(inode_buffer, sfs_inode, sizeof(*inode_buffer));
	}

//      mutex_unlock(&simplefs_inodes_mgmt_lock);

	brelse(bh);
	return inode_buffer;
}

/* Save the modified inode */
int simplefs_inode_save(struct super_block *sb, struct simplefs_inode *sfs_inode)
{
	struct simplefs_inode *inode_iterator;
	struct buffer_head *bh;

	bh = sb_bread(sb, SIMPLEFS_INODESTORE_BLOCK_NUMBER);
	BUG_ON(!bh);

	if (mutex_lock_interruptible(&simplefs_sb_lock)) {
		sfs_trace("Failed to acquire mutex lock\n");
		return -EINTR;
	}

	inode_iterator = simplefs_inode_search(sb,
		(struct simplefs_inode *)bh->b_data,
		sfs_inode);

	if (likely(inode_iterator)) {
		memcpy(inode_iterator, sfs_inode, sizeof(*inode_iterator));
		printk(KERN_INFO "The inode updated\n");

		mark_buffer_dirty(bh);
		sync_dirty_buffer(bh);
	} else {
		mutex_unlock(&simplefs_sb_lock);
		printk(KERN_ERR
		       "The new filesize could not be stored to the inode.");
		return -EIO;
	}

	brelse(bh);

	mutex_unlock(&simplefs_sb_lock);

	return 0;
}

static ssize_t simplefs_file_read_iter(struct kiocb *iocb, struct iov_iter *to)
{
	return generic_file_read_iter(iocb, to);
}

static ssize_t simplefs_file_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	return generic_file_write_iter(iocb, from);
}


const struct file_operations simplefs_file_operations = {
		.llseek		= generic_file_llseek,
		.read_iter	= simplefs_file_read_iter,
		.write_iter	= simplefs_file_write_iter,
		.mmap		= generic_file_mmap,
		.fsync		= generic_file_fsync,
		.get_unmapped_area = thp_get_unmapped_area,
		.splice_read	= generic_file_splice_read,
		.splice_write	= iter_file_splice_write,
};

const struct file_operations simplefs_dir_operations = {
	.owner = THIS_MODULE,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 11, 0)
	.iterate = simplefs_iterate,
#else
	.readdir = simplefs_readdir,
#endif
};

static int simplefs_unlink(struct inode * dir, struct dentry *dentry);
static int simplefs_rmdir (struct inode * dir, struct dentry *dentry);
static int simplefs_link (struct dentry * old_dentry, struct inode * dir,
				struct dentry *dentry);
static int simplefs_symlink (struct inode * dir, struct dentry * dentry,
				const char * symname);
struct dentry *simplefs_lookup(struct inode *parent_inode,
			       struct dentry *child_dentry, unsigned int flags);

static int simplefs_create(struct inode *dir, struct dentry *dentry,
			   umode_t mode, bool excl);

static int simplefs_mkdir(struct inode *dir, struct dentry *dentry,
			  umode_t mode);

static int simplefs_setattr(struct dentry *dentry, struct iattr *iattr);


static struct inode_operations simplefs_file_inode_ops = {
	.setattr	= simplefs_setattr,
};

static struct inode_operations simplefs_dir_inode_ops = {
	.create = simplefs_create,
	.link = simplefs_link,
	.unlink = simplefs_unlink,
	.symlink = simplefs_symlink,
	.rmdir = simplefs_rmdir,
	.lookup = simplefs_lookup,
	.mkdir = simplefs_mkdir,
};

static struct inode_operations simplefs_link_inode_ops = {
		.get_link = page_get_link,
		.setattr = simplefs_setattr,
};

static void simplefs_write_failed(struct address_space *mapping, loff_t to)
{
	printk(KERN_DEBUG "simplefs_write_failed\n");
	struct inode *inode = mapping->host;

	if (to > inode->i_size)
	{
		truncate_pagecache(inode, inode->i_size);
	}
}

static int simplefs_get_block(struct inode *inode, sector_t iblock,
		struct buffer_head *bh_result, int create)
{
	struct simplefs_inode *sfs_inode;
	uint64_t bno;
	sfs_inode = SIMPLEFS_INODE(inode);

	bno = sfs_inode->data_block_number;
	map_bh(bh_result, inode->i_sb, bno);
	bh_result->b_size = SIMPLEFS_DEFAULT_BLOCK_SIZE;

	return 0;
}

static int simplefs_writepage(struct page *page, struct writeback_control *wbc)
{
	printk(KERN_DEBUG "simplefs_writepage\n");
	return block_write_full_page(page, simplefs_get_block, wbc);
}

static int simplefs_readpage(struct file *file, struct page *page)
{
	printk(KERN_DEBUG "simplefs_readpage\n");
	return mpage_readpage(page, simplefs_get_block);
}

static int simplefs_readpages(struct file *file, struct address_space *mapping,
		struct list_head *pages, unsigned nr_pages)
{
	printk(KERN_DEBUG "simplefs_readpages\n");
	return mpage_readpages(mapping, pages, nr_pages, simplefs_get_block);
}

static int simplefs_write_begin(struct file *file, struct address_space *mapping,
		loff_t pos, unsigned len, unsigned flags, struct page **pagep, void **fsdata)
{
	int ret;

	printk(KERN_DEBUG "simplefs_write_begin\n");

	ret = block_write_begin(mapping, pos, len, flags, pagep,
			simplefs_get_block);
	if (ret < 0)
		simplefs_write_failed(mapping, pos + len);
	return ret;
}

static int simplefs_write_end(struct file *file, struct address_space *mapping,
			loff_t pos, unsigned len, unsigned copied, struct page *page, void *fsdata)
{
	int ret;

	printk(KERN_DEBUG "simplefs_write_end, %lld, %u, %u\n", pos, len, copied);

	ret = generic_write_end(file, mapping, pos, len, copied, page, fsdata);
	if (ret < len)
		simplefs_write_failed(mapping, pos + len);
	return ret;
}

static sector_t simplefs_bmap(struct address_space *mapping, sector_t block)
{
	printk(KERN_DEBUG "simplefs_bmap\n");
	return generic_block_bmap(mapping, block, simplefs_get_block);
}

static ssize_t simplefs_direct_IO(struct kiocb *iocb, struct iov_iter *iter)
{
	struct file *file = iocb->ki_filp;
	struct address_space *mapping = file->f_mapping;
	struct inode *inode = mapping->host;
	size_t count = iov_iter_count(iter);
	loff_t offset = iocb->ki_pos;
	ssize_t ret;

	if (WARN_ON_ONCE(IS_DAX(inode)))
		return -EIO;

	printk(KERN_DEBUG "simplefs_direct_IO\n");

	ret = blockdev_direct_IO(iocb, inode, iter, simplefs_get_block);
	if (ret < 0 && iov_iter_rw(iter) == WRITE)
		simplefs_write_failed(mapping, offset + count);
	return ret;
}

static int simplefs_writepages(struct address_space *mapping,
								struct writeback_control *wbc)
{
	printk(KERN_DEBUG "simplefs_writepages\n");
	return mpage_writepages(mapping, wbc, simplefs_get_block);
}


static struct address_space_operations simplefs_aops = {
		.readpage		= simplefs_readpage,
		.readpages		= simplefs_readpages,
		.writepage		= simplefs_writepage,
		.write_begin		= simplefs_write_begin,
		.write_end		= simplefs_write_end,
		.bmap			= simplefs_bmap,
		.direct_IO		= simplefs_direct_IO,
		.writepages		= simplefs_writepages,
		.migratepage		= buffer_migrate_page,
		.is_partially_uptodate	= block_is_partially_uptodate,
		.error_remove_page	= generic_error_remove_page,
};

static int simplefs_commit_chunk(struct page *page, loff_t pos, unsigned len)
{
	struct address_space *mapping = page->mapping;
	struct inode *inode = mapping->host;
	int err = 0;

	inode->i_version++;
	block_write_end(NULL, mapping, pos, len, len, page, NULL);

	if (pos+len > inode->i_size)
	{
		i_size_write(inode, pos+len);
		mark_inode_dirty(inode);
	}

	err = write_one_page(page);
	if (!err)
		err = sync_inode_metadata(inode, 1);

	return err;
}

static int simplefs_add_entry(struct dentry *dentry, struct inode *inode)
{
	struct inode *dir = d_inode(dentry->d_parent);
	struct page *page = NULL;
	struct simplefs_dir_record *dir_contents_datablock;

	char *kaddr;
	loff_t pos;
	int err;
	int i;

	/*
	 * We take care of directory expansion in the same loop.
	 * This code plays outside i_size, so it locks the page
	 * to protect that region.
	 */
	page = simplefs_get_page(dir, 0);
	err = PTR_ERR(page);
	if (IS_ERR(page))
		goto out;
	lock_page(page);
	kaddr = page_address(page);
	dir_contents_datablock = (struct simplefs_dir_record *)kaddr;
	/* Navigate to the last record in the directory contents */
	for(i=0; i<SIMPLEFS_MAX_DIR_RECORD_COUNT; i++)
	{
		if(dir_contents_datablock->inode_no == 0)
		{
			break;
		}
		dir_contents_datablock++;
	}

	if(i == SIMPLEFS_MAX_DIR_RECORD_COUNT)
	{
		printk(KERN_ERR
				"Maximum number of dir record supported by simplefs is already reached");
		err = -ENOSPC;
		goto out_unlock;
	}

	pos = (char*)dir_contents_datablock - (char*)page_address(page);
	err = __block_write_begin(page, pos, sizeof(struct simplefs_dir_record), simplefs_get_block);
	if (err)
		goto out_unlock;

	dir_contents_datablock->inode_no = inode->i_ino;
	strcpy(dir_contents_datablock->filename, dentry->d_name.name);

	err = simplefs_commit_chunk(page, pos, sizeof(struct simplefs_dir_record));
	dir->i_mtime = dir->i_ctime = current_time(dir);
	/* OFFSET_CACHE */
out_put:
	simplefs_put_page(page);
out:
	return err;
out_unlock:
	unlock_page(page);
	goto out_put;
}

static int simplefs_create_fs_object(struct inode *dir, struct dentry *dentry,
				     umode_t mode, unsigned size, struct inode **out)
{
	struct inode *inode;
	struct simplefs_inode *sfs_inode;
	struct super_block *sb;
	struct simplefs_inode *parent_dir_inode;
	uint64_t count;
	uint64_t next_inode_no;
	int ret;
	int isclear_data;

	if (mutex_lock_interruptible(&simplefs_directory_children_update_lock)) {
		sfs_trace("Failed to acquire mutex lock\n");
		return -EINTR;
	}
	sb = dir->i_sb;

	ret = simplefs_sb_get_objects_count(sb, &count, &next_inode_no);
	if (ret < 0) {
		mutex_unlock(&simplefs_directory_children_update_lock);
		return ret;
	}

	if (unlikely(count >= SIMPLEFS_MAX_FILESYSTEM_OBJECTS_SUPPORTED
			|| next_inode_no > SIMPLEFS_MAX_FILESYSTEM_OBJECTS_SUPPORTED)) {
		/* The above condition can be just == insted of the >= */
		printk(KERN_ERR
		       "Maximum number of objects supported by simplefs is already reached");
		mutex_unlock(&simplefs_directory_children_update_lock);
		return -ENOSPC;
	}

	if (!S_ISDIR(mode) && !S_ISREG(mode) && !S_ISLNK(mode)) {
		printk(KERN_ERR
		       "Creation request but for neither a file nor a directory");
		mutex_unlock(&simplefs_directory_children_update_lock);
		return -EINVAL;
	}

	inode = new_inode(sb);
	if (!inode) {
		mutex_unlock(&simplefs_directory_children_update_lock);
		return -ENOMEM;
	}

	inode->i_sb = sb;
	inode->i_atime = inode->i_mtime = inode->i_ctime = current_time(inode);
	inode->i_ino = next_inode_no;
	inode->i_blocks = 1;
	inode->i_size = size;
	inode->i_flags |= S_SYNC;

	sfs_inode = kmem_cache_alloc(sfs_inode_cachep, GFP_KERNEL);
	sfs_inode->inode_no = inode->i_ino;
	sfs_inode->file_size = size;
	inode->i_private = sfs_inode;
	sfs_inode->mode = mode;

	isclear_data = 0;
	if (S_ISDIR(mode)) {
		printk(KERN_INFO "New directory creation request\n");
		sfs_inode->dir_children_count = 0;
		inode->i_fop = &simplefs_dir_operations;
		inode->i_op = &simplefs_dir_inode_ops;
		inode->i_mapping->a_ops = &simplefs_aops;
		isclear_data = 1;
	} else if (S_ISREG(mode)) {
		printk(KERN_INFO "New file creation request\n");
		inode->i_fop = &simplefs_file_operations;
		inode->i_op = &simplefs_file_inode_ops;
		inode->i_mapping->a_ops = &simplefs_aops;
	}
	else if(S_ISLNK(mode))
	{
		printk(KERN_INFO "New link creation request\n");
		inode->i_fop = NULL;
		inode->i_op = &simplefs_link_inode_ops;
		inode->i_mapping->a_ops = &simplefs_aops;
		inode_nohighmem(inode);
	}

	/* First get a free block and update the free map,
	 * Then add inode to the inode store and update the sb inodes_count,
	 * Then update the parent directory's inode with the new child.
	 *
	 * The above ordering helps us to maintain fs consistency
	 * even in most crashes
	 */
	ret = simplefs_sb_get_a_freeblock(sb, &sfs_inode->data_block_number, isclear_data);
	if (ret < 0)
	{
		printk(KERN_ERR "simplefs could not get a freeblock");
		mutex_unlock(&simplefs_directory_children_update_lock);
		return ret;
	}

	simplefs_inode_add(sb, sfs_inode);

	if (mutex_lock_interruptible(&simplefs_inodes_mgmt_lock))
	{
		mutex_unlock(&simplefs_directory_children_update_lock);
		sfs_trace("Failed to acquire mutex lock\n");
		return -EINTR;
	}

	parent_dir_inode = SIMPLEFS_INODE(dir);
	parent_dir_inode->dir_children_count++;

	mark_inode_dirty(dir);

	mutex_unlock(&simplefs_inodes_mgmt_lock);

	ret = simplefs_add_entry(dentry, inode);
	if(ret < 0)
	{
		printk(KERN_ERR "simplefs could not update parent inode");
		mutex_unlock(&simplefs_directory_children_update_lock);
		return ret;
	}

	mutex_unlock(&simplefs_directory_children_update_lock);

	inode_init_owner(inode, dir, mode);
	d_add(dentry, inode);

	mark_inode_dirty(inode);

	if(out)
	{
		*out = inode;
	}
	return 0;
}

static int simplefs_find_entry(struct inode *dir, unsigned long inode_no)
{
	struct page *page = NULL;
	struct simplefs_dir_record *dir_contents_datablock;
	char *kaddr;
	int err;
	int i;
	int ref_count = 0;

	page = simplefs_get_page(dir, 0);
	err = PTR_ERR(page);
	if (IS_ERR(page))
		goto out_put;
	lock_page(page);
	kaddr = page_address(page);
	dir_contents_datablock = (struct simplefs_dir_record *)kaddr;
	for(i=0; i<SIMPLEFS_MAX_DIR_RECORD_COUNT; i++)
	{
		if(dir_contents_datablock->inode_no == inode_no)
			ref_count++;

		dir_contents_datablock++;
	}

out_put:
	unlock_page(page);
	simplefs_put_page(page);

	return ref_count;
}

static int simplefs_delete_entry(struct dentry *dentry, struct inode *inode)
{
	struct inode *dir = d_inode(dentry->d_parent);
	const char *name = dentry->d_name.name;
	int namelen = dentry->d_name.len;
	struct page *page = NULL;
	struct simplefs_dir_record *dir_contents_datablock;
	char *kaddr;
	loff_t pos;
	int err;
	int i;

	/*
	 * We take care of directory expansion in the same loop.
	 * This code plays outside i_size, so it locks the page
	 * to protect that region.
	 */
	page = simplefs_get_page(dir, 0);
	err = PTR_ERR(page);
	if (IS_ERR(page))
		goto out;
	lock_page(page);
	kaddr = page_address(page);
	dir_contents_datablock = (struct simplefs_dir_record *)kaddr;
	for(i=0; i<SIMPLEFS_MAX_DIR_RECORD_COUNT; i++)
	{
		if(dir_contents_datablock->inode_no == inode->i_ino
			&& namelen == strlen(dir_contents_datablock->filename)
			&& memcmp(dir_contents_datablock->filename, name, namelen) == 0)
			break;

		dir_contents_datablock++;
	}

	if(i == SIMPLEFS_MAX_DIR_RECORD_COUNT)
	{
		printk(KERN_ERR
				"can't find expected entry in parent dir.\n");
		err = -ENOSPC;
		goto out_unlock;
	}

	pos = (char*)dir_contents_datablock - (char*)page_address(page);
	err = __block_write_begin(page, pos, sizeof(struct simplefs_dir_record), simplefs_get_block);
	if (err)
		goto out_unlock;

	dir_contents_datablock->inode_no = 0;

	err = simplefs_commit_chunk(page, pos, sizeof(struct simplefs_dir_record));
	dir->i_mtime = dir->i_ctime = current_time(dir);

	/* OFFSET_CACHE */
out_put:
	simplefs_put_page(page);
out:
	return err;
out_unlock:
	unlock_page(page);
	goto out_put;
}

static int simplefs_remove_fs_object(struct inode *parent_dir, struct dentry *dentry)
{
	struct inode *inode;
	struct simplefs_inode *sfs_inode;
	struct super_block *sb;
	struct simplefs_inode *parent_dir_inode;
	int ret;

	if (mutex_lock_interruptible(&simplefs_directory_children_update_lock)) {
		sfs_trace("Failed to acquire mutex lock\n");
		return -EINTR;
	}
	sb = parent_dir->i_sb;
	inode = dentry->d_inode;
	sfs_inode = SIMPLEFS_INODE(dentry->d_inode);

	if(simplefs_find_entry(parent_dir, inode->i_ino) == 1)
	{
		/* Remove data block */
		ret = simplefs_sb_release_a_datablock(sb, sfs_inode->data_block_number);
		if (ret < 0) {
			printk(KERN_ERR "simplefs could not release datablock");
			mutex_unlock(&simplefs_directory_children_update_lock);
			return ret;
		}

		/* Release inode from inode table */
		simplefs_inode_del(sb, sfs_inode);
	}

	if (mutex_lock_interruptible(&simplefs_inodes_mgmt_lock)) {
		mutex_unlock(&simplefs_directory_children_update_lock);
		sfs_trace("Failed to acquire mutex lock\n");
		return -EINTR;
	}

	/* Reduce the children count from parent dir  */
	parent_dir_inode = SIMPLEFS_INODE(parent_dir);
	parent_dir_inode->dir_children_count--;
	mark_inode_dirty(parent_dir);

	mutex_unlock(&simplefs_inodes_mgmt_lock);

	/* Remove from parent dir data block */
	ret = simplefs_delete_entry(dentry, inode);
	if(ret < 0)
	{
		printk(KERN_ERR "simplefs could not update parent inode");
		mutex_unlock(&simplefs_directory_children_update_lock);
		return ret;
	}

	mutex_unlock(&simplefs_directory_children_update_lock);

	inode_dec_link_count(inode);
	return 0;
}

static int simplefs_unlink(struct inode * parent_dir, struct dentry *dentry)
{
	printk(KERN_DEBUG "simplefs_unlink parent dir inode=%lu, name=%s\n", parent_dir->i_ino, dentry->d_name.name);
	return simplefs_remove_fs_object(parent_dir, dentry);
}

static int simplefs_rmdir (struct inode * parent_dir, struct dentry *dentry)
{
	printk(KERN_DEBUG "simplefs_rmdir inode=%lu, name=%s\n", parent_dir->i_ino, dentry->d_name.name);
	struct simplefs_inode *sfs_inode;
	sfs_inode = SIMPLEFS_INODE(dentry->d_inode);
	if(sfs_inode->dir_children_count > 0)
		return -ENOTEMPTY;

	return simplefs_remove_fs_object(parent_dir, dentry);
}


static int simplefs_link (struct dentry * old_dentry, struct inode * dir,
				struct dentry *dentry)
{
	printk(KERN_DEBUG "simplefs_link inode=%lu, oldname=%s, name=%s\n",
			dir->i_ino, old_dentry->d_name.name, dentry->d_name.name);
	struct inode *inode = d_inode(old_dentry);
	struct super_block *sb;
	struct simplefs_inode *parent_dir_inode;
	int err;

	if (mutex_lock_interruptible(&simplefs_directory_children_update_lock)) {
		sfs_trace("Failed to acquire mutex lock\n");
		return -EINTR;
	}
	sb = dir->i_sb;

	inode->i_ctime = current_time(inode);
	inode_inc_link_count(inode);
	ihold(inode);

	if (mutex_lock_interruptible(&simplefs_inodes_mgmt_lock)) {
		mutex_unlock(&simplefs_directory_children_update_lock);
		sfs_trace("Failed to acquire mutex lock\n");
		return -EINTR;
	}

	parent_dir_inode = SIMPLEFS_INODE(dir);
	parent_dir_inode->dir_children_count++;
	mark_inode_dirty(dir);

	mutex_unlock(&simplefs_inodes_mgmt_lock);

	err = simplefs_add_entry(dentry, inode);
	if(err < 0)
	{
		printk(KERN_ERR "simplefs could not update parent inode");
		mutex_unlock(&simplefs_directory_children_update_lock);
		return err;
	}

	mutex_unlock(&simplefs_directory_children_update_lock);

	if (!err) {
		d_add(dentry, inode);
		return 0;
	}
	inode_dec_link_count(inode);
	iput(inode);

	return err;
}

static int simplefs_symlink (struct inode * dir, struct dentry * dentry,
				const char * symname)
{
	int err;
	struct inode *inode = NULL;
	unsigned l = strlen(symname)+1;
	struct page *page;

	printk(KERN_DEBUG "simplefs_symlink inode=%lu, name=%s, symname=%s\n",
				dir->i_ino, dentry->d_name.name, symname);
	err = simplefs_create_fs_object(dir, dentry, S_IFLNK | S_IRWXUGO, l, &inode);
	if(err)
		goto out;

	/* Set data with symname */
	err = page_symlink(inode, symname, l);
	if(err)
		goto out_fail;

	page = simplefs_get_page(inode, 0);
	err = PTR_ERR(page);
	if (IS_ERR(page))
		goto out_fail;

	/* Commit changes */
	lock_page(page);
	err = simplefs_commit_chunk(page, 0, l);
	unlock_page(page);

out:
	return err;

out_fail:
	inode_dec_link_count(inode);
	unlock_new_inode(inode);
	iput (inode);
	goto out;
}

static int simplefs_mkdir(struct inode *dir, struct dentry *dentry,
			  umode_t mode)
{
	/* I believe this is a bug in the kernel, for some reason, the mkdir callback
	 * does not get the S_IFDIR flag set. Even ext2 sets is explicitly */
	printk(KERN_DEBUG "simplefs_mkdir parent dir inode=%lu, name=%s\n", dir->i_ino, dentry->d_name.name);
	return simplefs_create_fs_object(dir, dentry, S_IFDIR | mode, SIMPLEFS_DEFAULT_BLOCK_SIZE, NULL);
}

static int simplefs_create(struct inode *dir, struct dentry *dentry,
			   umode_t mode, bool excl)
{
	printk(KERN_DEBUG "simplefs_create parent dir inode=%lu, name=%s\n", dir->i_ino, dentry->d_name.name);
	return simplefs_create_fs_object(dir, dentry, mode, 0, NULL);
}

struct dentry *simplefs_lookup(struct inode *parent_inode,
			       struct dentry *child_dentry, unsigned int flags)
{
	struct page *page = NULL;
	struct super_block *sb = parent_inode->i_sb;
	struct simplefs_inode *parent = SIMPLEFS_INODE(parent_inode);
	struct simplefs_dir_record *record;
	struct inode *inode = NULL;
	char *kaddr;
	char *endaddr;
	int err;
	int i;

	/*
	 * We take care of directory expansion in the same loop.
	 * This code plays outside i_size, so it locks the page
	 * to protect that region.
	 */
	page = simplefs_get_page(parent_inode, 0);
	err = PTR_ERR(page);
	if (IS_ERR(page))
		return ERR_PTR(err);
	lock_page(page);
	kaddr = page_address(page);
	record = (struct simplefs_dir_record *)kaddr;
	endaddr = kaddr + parent_inode->i_size;
	for (i = 0; i < parent->dir_children_count && (char*)record < endaddr; record++)
	{
		if(record->inode_no == 0)
			continue;

		if (!strcmp(record->filename, child_dentry->d_name.name))
		{
			/* FIXME: There is a corner case where if an allocated inode,
			 * is not written to the inode store, but the inodes_count is
			 * incremented. Then if the random string on the disk matches
			 * with the filename that we are comparing above, then we
			 * will use an invalid uninitialized inode */


			struct simplefs_inode *sfs_inode;

			sfs_inode = simplefs_get_inode(sb, record->inode_no);

			inode = new_inode(sb);
			inode->i_ino = record->inode_no;
			inode_init_owner(inode, parent_inode, sfs_inode->mode);
			inode->i_sb = sb;
			inode->i_blocks = 1;
			inode->i_flags |= S_SYNC;
			inode->i_size = 0;

			if (S_ISDIR(inode->i_mode))
			{
				inode->i_fop = &simplefs_dir_operations;
				inode->i_op = &simplefs_dir_inode_ops;
				inode->i_mapping->a_ops = &simplefs_aops;
				inode->i_size = SIMPLEFS_DEFAULT_BLOCK_SIZE;
			}
			else if (S_ISREG(inode->i_mode))
			{
				inode->i_fop = &simplefs_file_operations;
				inode->i_op = &simplefs_file_inode_ops;
				inode->i_mapping->a_ops = &simplefs_aops;
				inode->i_size = sfs_inode->file_size;
			}
			else if (S_ISLNK(inode->i_mode))
			{
				inode->i_fop = NULL;
				inode->i_op = &simplefs_link_inode_ops;
				inode->i_mapping->a_ops = &simplefs_aops;
				inode->i_size = sfs_inode->file_size;
				inode_nohighmem(inode);
			}
			else
				printk(KERN_ERR
						"Unknown inode type. Neither a directory nor a file");

			/* FIXME: We should store these times to disk and retrieve them */
			inode->i_atime = inode->i_mtime = inode->i_ctime =
					current_time(inode);

			inode->i_private = sfs_inode;
			break;
		}

		i++;
	}

	unlock_page(page);
	simplefs_put_page(page);

	if(inode)
		return d_splice_alias(inode, child_dentry);
	else
		return NULL;
}

static int simplefs_setsize(struct inode *inode, loff_t newsize)
{
	int error;

	if (!(S_ISREG(inode->i_mode) || S_ISLNK(inode->i_mode)))
		return -EINVAL;
	if (IS_APPEND(inode) || IS_IMMUTABLE(inode))
		return -EPERM;

	inode_dio_wait(inode);

	error = block_truncate_page(inode->i_mapping,
			newsize, simplefs_get_block);

	if (error)
		return error;

	truncate_setsize(inode, newsize);

	inode->i_mtime = inode->i_ctime = current_time(inode);
	sync_mapping_buffers(inode->i_mapping);
	sync_inode_metadata(inode, 1);

	return 0;
}

static int simplefs_setattr(struct dentry *dentry, struct iattr *iattr)
{
	printk(KERN_DEBUG "simplefs setattr %s\n", dentry->d_name.name);
	struct inode *inode = d_inode(dentry);
	int error;

	error = setattr_prepare(dentry, iattr);
	if (error)
		return error;

	if (is_quota_modification(inode, iattr)) {
		error = dquot_initialize(inode);
		if (error)
			return error;
	}
	if ((iattr->ia_valid & ATTR_UID && !uid_eq(iattr->ia_uid, inode->i_uid)) ||
	    (iattr->ia_valid & ATTR_GID && !gid_eq(iattr->ia_gid, inode->i_gid))) {
		error = dquot_transfer(inode, iattr);
		if (error)
			return error;
	}

	if (iattr->ia_valid & ATTR_SIZE && iattr->ia_size != inode->i_size)
	{
		error = simplefs_setsize(inode, iattr->ia_size);
		if (error)
			return error;
	}

	setattr_copy(inode, iattr);
	if (iattr->ia_valid & ATTR_MODE)
	{
		error = posix_acl_chmod(inode, inode->i_mode);
		if(error)
			return error;
	}

	return error;
}


/**
 * Simplest
 */
void simplefs_destory_inode(struct inode *inode)
{
	struct simplefs_inode *sfs_inode = SIMPLEFS_INODE(inode);

	printk(KERN_INFO "Freeing private data of inode %p (%lu)\n",
	       sfs_inode, inode->i_ino);
	kmem_cache_free(sfs_inode_cachep, sfs_inode);
}

int simplefs_write_inode(struct inode *inode, struct writeback_control *wbc)
{
	printk(KERN_DEBUG "simplefs_write_inode: %lu\n", inode->i_ino);
	int err;
	struct simplefs_inode *sfs_inode;

	if (mutex_lock_interruptible(&simplefs_inodes_mgmt_lock))
	{
		mutex_unlock(&simplefs_directory_children_update_lock);
		sfs_trace("Failed to acquire mutex lock\n");
		return -EINTR;
	}

	sfs_inode = SIMPLEFS_INODE(inode);
	sfs_inode->mode = inode->i_mode;

	if(S_ISREG(inode->i_mode) || S_ISLNK(inode->i_mode))
		sfs_inode->file_size = inode->i_size;
	err = simplefs_inode_save(inode->i_sb, sfs_inode);

	mutex_unlock(&simplefs_inodes_mgmt_lock);
	return err;
}

static const struct super_operations simplefs_sops = {
	.destroy_inode = simplefs_destory_inode,
	.write_inode	= simplefs_write_inode,
};

/* This function, as the name implies, Makes the super_block valid and
 * fills filesystem specific information in the super block */
int simplefs_fill_super(struct super_block *sb, void *data, int silent)
{
	struct inode *root_inode;
	struct buffer_head *bh;
	struct simplefs_super_block *sb_disk;
	int ret = -EPERM;

	printk(KERN_DEBUG "simplefs_fill_super\n");

	bh = sb_bread(sb, SIMPLEFS_SUPERBLOCK_BLOCK_NUMBER);
	BUG_ON(!bh);

	sb_disk = (struct simplefs_super_block *)bh->b_data;

	printk(KERN_INFO "The magic number obtained in disk is: [%llu]\n",
	       sb_disk->magic);

	if (unlikely(sb_disk->magic != SIMPLEFS_MAGIC)) {
		printk(KERN_ERR
		       "The filesystem that you try to mount is not of type simplefs. Magicnumber mismatch.");
		goto release;
	}

	if (unlikely(sb_disk->block_size != SIMPLEFS_DEFAULT_BLOCK_SIZE)) {
		printk(KERN_ERR
		       "simplefs seem to be formatted using a non-standard block size.");
		goto release;
	}

	printk(KERN_INFO
	       "simplefs filesystem of version [%llu] formatted with a block size of [%llu] detected in the device.\n",
	       sb_disk->version, sb_disk->block_size);

	/* A magic number that uniquely identifies our filesystem type */
	sb->s_magic = SIMPLEFS_MAGIC;

	/* For all practical purposes, we will be using this s_fs_info as the super block */
	sb->s_fs_info = sb_disk;

	sb->s_maxbytes = SIMPLEFS_DEFAULT_BLOCK_SIZE;
	sb_set_blocksize(sb, SIMPLEFS_DEFAULT_BLOCK_SIZE);
	sb->s_op = &simplefs_sops;

	root_inode = new_inode(sb);
	root_inode->i_ino = SIMPLEFS_ROOTDIR_INODE_NUMBER;
	inode_init_owner(root_inode, NULL, S_IFDIR);
	root_inode->i_sb = sb;
	root_inode->i_op = &simplefs_dir_inode_ops;
	root_inode->i_fop = &simplefs_dir_operations;
	root_inode->i_mapping->a_ops = &simplefs_aops;
	root_inode->i_atime = root_inode->i_mtime = root_inode->i_ctime =
	    current_time(root_inode);
	root_inode->i_blocks = 1;
	root_inode->i_size = SIMPLEFS_DEFAULT_BLOCK_SIZE;
	root_inode->i_flags |= S_SYNC;
	root_inode->i_private =
	    simplefs_get_inode(sb, SIMPLEFS_ROOTDIR_INODE_NUMBER);

	/* TODO: move such stuff into separate header. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 3, 0)
	sb->s_root = d_make_root(root_inode);
#else
	sb->s_root = d_alloc_root(root_inode);
	if (!sb->s_root)
		iput(root_inode);
#endif

	if (!sb->s_root) {
		ret = -ENOMEM;
		goto release;
	}

	ret = 0;
release:
	brelse(bh);

	return ret;
}

static struct dentry *simplefs_mount(struct file_system_type *fs_type,
				     int flags, const char *dev_name,
				     void *data)
{
	struct dentry *ret;
	printk(KERN_DEBUG "simplefs_mount dev_name=%s\n", dev_name);
	ret = mount_bdev(fs_type, flags, dev_name, data, simplefs_fill_super);

	if (unlikely(IS_ERR(ret)))
		printk(KERN_ERR "Error mounting simplefs");
	else
		printk(KERN_INFO "simplefs is succesfully mounted on [%s]\n",
		       dev_name);

	return ret;
}

static void simplefs_kill_superblock(struct super_block *sb)
{
	printk(KERN_INFO
	       "simplefs superblock is destroyed. Unmount succesful.\n");
	/* This is just a dummy function as of now. As our filesystem gets matured,
	 * we will do more meaningful operations here */

	kill_block_super(sb);
	return;
}

struct file_system_type simplefs_fs_type = {
	.owner = THIS_MODULE,
	.name = "simplefs",
	.mount = simplefs_mount,
	.kill_sb = simplefs_kill_superblock,
	.fs_flags = FS_REQUIRES_DEV,
};

static int simplefs_init(void)
{
	int ret;

	sfs_inode_cachep = kmem_cache_create("sfs_inode_cache",
	                                     sizeof(struct simplefs_inode),
	                                     0,
	                                     (SLAB_RECLAIM_ACCOUNT| SLAB_MEM_SPREAD),
	                                     NULL);
	if (!sfs_inode_cachep) {
		return -ENOMEM;
	}

	ret = register_filesystem(&simplefs_fs_type);
	if (likely(ret == 0))
		printk(KERN_INFO "Sucessfully registered simplefs\n");
	else
		printk(KERN_ERR "Failed to register simplefs. Error:[%d]", ret);

	return ret;
}

static void simplefs_exit(void)
{
	int ret;

	ret = unregister_filesystem(&simplefs_fs_type);
	kmem_cache_destroy(sfs_inode_cachep);

	if (likely(ret == 0))
		printk(KERN_INFO "Sucessfully unregistered simplefs\n");
	else
		printk(KERN_ERR "Failed to unregister simplefs. Error:[%d]",
		       ret);
}

module_init(simplefs_init);
module_exit(simplefs_exit);

MODULE_LICENSE("CC0");
MODULE_AUTHOR("Sankar P");
