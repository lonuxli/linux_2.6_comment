/*
 * mm/readahead.c - address_space-level file readahead.
 *
 * Copyright (C) 2002, Linus Torvalds
 *
 * 09Apr2002	akpm@zip.com.au
 *		Initial version.
 */

#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/blkdev.h>
#include <linux/backing-dev.h>
#include <linux/pagevec.h>

void default_unplug_io_fn(struct backing_dev_info *bdi, struct page *page)
{
}
EXPORT_SYMBOL(default_unplug_io_fn);

struct backing_dev_info default_backing_dev_info = {
	.ra_pages	= (VM_MAX_READAHEAD * 1024) / PAGE_CACHE_SIZE,
	.state		= 0,
	.unplug_io_fn	= default_unplug_io_fn,
};
EXPORT_SYMBOL_GPL(default_backing_dev_info);

/*
 * Initialise a struct file's readahead state.  Assumes that the caller has
 * memset *ra to zero.
 */
void
file_ra_state_init(struct file_ra_state *ra, struct address_space *mapping)
{
	ra->ra_pages = mapping->backing_dev_info->ra_pages;
	ra->prev_page = -1;
}

/*
 * Return max readahead size for this inode in number-of-pages.
 */
static inline unsigned long get_max_readahead(struct file_ra_state *ra)
{
	return ra->ra_pages;
}

static inline unsigned long get_min_readahead(struct file_ra_state *ra)
{
	return (VM_MIN_READAHEAD * 1024) / PAGE_CACHE_SIZE;
}

static inline void ra_off(struct file_ra_state *ra)
{
	ra->start = 0;
	ra->flags = 0;
	ra->size = -1;
	ra->ahead_start = 0;
	ra->ahead_size = 0;
	return;
}

/*
 * Set the initial window size, round to next power of 2 and square
 * for small size, x 4 for medium, and x 2 for large
 * for 128k (32 page) max ra
 * 1-8 page = 32k initial, > 8 page = 128k initial
 */
static unsigned long get_init_ra_size(unsigned long size, unsigned long max)
{
	unsigned long newsize = roundup_pow_of_two(size);

	if (newsize <= max / 64)
		newsize = newsize * newsize;
	else if (newsize <= max / 4)
		newsize = max / 4;
	else
		newsize = max;
	return newsize;
}

/*
 * Set the new window size, this is called only when I/O is to be submitted,
 * not for each call to readahead.  If a cache miss occured, reduce next I/O
 * size, else increase depending on how close to max we are.
 */
static unsigned long get_next_ra_size(unsigned long cur, unsigned long max,
				unsigned long min, unsigned long * flags)
{
	unsigned long newsize;

	if (*flags & RA_FLAG_MISS) {
		newsize = max((cur - 2), min);
		*flags &= ~RA_FLAG_MISS;
	} else if (cur < max / 16) {
		newsize = 4 * cur;
	} else {
		newsize = 2 * cur;
	}
	return min(newsize, max);
}

#define list_to_page(head) (list_entry((head)->prev, struct page, lru))

/**
 * read_cache_pages - populate an address space with some pages, and
 * 			start reads against them.
 * @mapping: the address_space
 * @pages: The address of a list_head which contains the target pages.  These
 *   pages have their ->index populated and are otherwise uninitialised.
 * @filler: callback routine for filling a single page.
 * @data: private data for the callback routine.
 *
 * Hides the details of the LRU cache etc from the filesystems.
 */
int read_cache_pages(struct address_space *mapping, struct list_head *pages,
			int (*filler)(void *, struct page *), void *data)
{
	struct page *page;
	struct pagevec lru_pvec;
	int ret = 0;

	pagevec_init(&lru_pvec, 0);

	while (!list_empty(pages)) {
		page = list_to_page(pages);
		list_del(&page->lru);
		if (add_to_page_cache(page, mapping, page->index, GFP_KERNEL)) {
			page_cache_release(page);
			continue;
		}
		ret = filler(data, page);
		if (!pagevec_add(&lru_pvec, page))
			__pagevec_lru_add(&lru_pvec);
		if (ret) {
			while (!list_empty(pages)) {
				struct page *victim;

				victim = list_to_page(pages);
				list_del(&victim->lru);
				page_cache_release(victim);
			}
			break;
		}
	}
	pagevec_lru_add(&lru_pvec);
	return ret;
}

EXPORT_SYMBOL(read_cache_pages);

static int read_pages(struct address_space *mapping, struct file *filp,
		struct list_head *pages, unsigned nr_pages)
{
	unsigned page_idx;
	struct pagevec lru_pvec;
	int ret = 0;

	if (mapping->a_ops->readpages) {
		ret = mapping->a_ops->readpages(filp, mapping, pages, nr_pages);
		goto out;
	}

	pagevec_init(&lru_pvec, 0);
	for (page_idx = 0; page_idx < nr_pages; page_idx++) {
		struct page *page = list_to_page(pages);
		list_del(&page->lru);
		if (!add_to_page_cache(page, mapping,
					page->index, GFP_KERNEL)) {
			mapping->a_ops->readpage(filp, page);
			if (!pagevec_add(&lru_pvec, page))
				__pagevec_lru_add(&lru_pvec);
		} else {
			page_cache_release(page);
		}
	}
	pagevec_lru_add(&lru_pvec);
out:
	return ret;
}

/*
 * Readahead design.
 *
 * The fields in struct file_ra_state represent the most-recently-executed
 * readahead attempt:
 *
 * start:	Page index at which we started the readahead
 * size:	Number of pages in that read
 *              Together, these form the "current window".
 *              Together, start and size represent the `readahead window'.
 * next_size:   The number of pages to read on the next readahead miss.
 *              Has the magical value -1UL if readahead has been disabled.
 * prev_page:   The page which the readahead algorithm most-recently inspected.
 *              prev_page is mainly an optimisation: if page_cache_readahead
 *		sees that it is again being called for a page which it just
 *		looked at, it can return immediately without making any state
 *		changes.
 * ahead_start,
 * ahead_size:  Together, these form the "ahead window".
 * ra_pages:	The externally controlled max readahead for this fd.
 *
 * When readahead is in the off state (size == -1UL), readahead is disabled.
 * In this state, prev_page is used to detect the resumption of sequential I/O.
 *
 * The readahead code manages two windows - the "current" and the "ahead"
 * windows.  The intent is that while the application is walking the pages
 * in the current window, I/O is underway on the ahead window.  When the
 * current window is fully traversed, it is replaced by the ahead window
 * and the ahead window is invalidated.  When this copying happens, the
 * new current window's pages are probably still locked.  So
 * we submit a new batch of I/O immediately, creating a new ahead window.
 *
 * So:
 *
 *   ----|----------------|----------------|-----
 *       ^start           ^start+size
 *                        ^ahead_start     ^ahead_start+ahead_size
 *
 *         ^ When this page is read, we submit I/O for the
 *           ahead window.
 *
 * A `readahead hit' occurs when a read request is made against a page which is
 * the next sequential page. Ahead windowe calculations are done only when it
 * is time to submit a new IO.  The code ramps up the size agressively at first,
 * but slow down as it approaches max_readhead.
 *
 * Any seek/ramdom IO will result in readahead being turned off.  It will resume
 * at the first sequential access.
 *
 * There is a special-case: if the first page which the application tries to
 * read happens to be the first page of the file, it is assumed that a linear
 * read is about to happen and the window is immediately set to the initial size
 * based on I/O request size and the max_readahead.
 * 
 * A page request at (start + size) is not a miss at all - it's just a part of
 * sequential file reading.
 *
 * This function is to be called for every read request, rather than when
 * it is time to perform readahead.  It is called only oce for the entire I/O
 * regardless of size unless readahead is unable to start enough I/O to satisfy
 * the request (I/O request > max_readahead).
 */

/*
 * do_page_cache_readahead actually reads a chunk of disk.  It allocates all
 * the pages first, then submits them all for I/O. This avoids the very bad
 * behaviour which would occur if page allocations are causing VM writeback.
 * We really don't want to intermingle reads and writes like that.
 *
 * Returns the number of pages requested, or the maximum amount of I/O allowed.
 *
 * do_page_cache_readahead() returns -1 if it encountered request queue
 * congestion.
 */
static int
__do_page_cache_readahead(struct address_space *mapping, struct file *filp,
			unsigned long offset, unsigned long nr_to_read)
{
	struct inode *inode = mapping->host;
	struct page *page;
	unsigned long end_index;	/* The last page we want to read */
	LIST_HEAD(page_pool);
	int page_idx;
	int ret = 0;
	loff_t isize = i_size_read(inode);

	if (isize == 0)
		goto out;

 	end_index = ((isize - 1) >> PAGE_CACHE_SHIFT);

	/*
	 * Preallocate as many pages as we will need.
	 */
	spin_lock_irq(&mapping->tree_lock);
	for (page_idx = 0; page_idx < nr_to_read; page_idx++) {
		unsigned long page_offset = offset + page_idx;
		
		if (page_offset > end_index)
			break;

		page = radix_tree_lookup(&mapping->page_tree, page_offset);
		if (page)
			continue;

		spin_unlock_irq(&mapping->tree_lock);
		page = page_cache_alloc_cold(mapping);
		spin_lock_irq(&mapping->tree_lock);
		if (!page)
			break;
		page->index = page_offset;
		list_add(&page->lru, &page_pool);
		ret++;
	}
	spin_unlock_irq(&mapping->tree_lock);

	/*
	 * Now start the IO.  We ignore I/O errors - if the page is not
	 * uptodate then the caller will launch readpage again, and
	 * will then handle the error.
	 */
	if (ret)
		read_pages(mapping, filp, &page_pool, ret);
	BUG_ON(!list_empty(&page_pool));
out:
	return ret;
}

/*
 * Chunk the readahead into 2 megabyte units, so that we don't pin too much
 * memory at once.
 */
int force_page_cache_readahead(struct address_space *mapping, struct file *filp,
		unsigned long offset, unsigned long nr_to_read)
{
	int ret = 0;

	if (unlikely(!mapping->a_ops->readpage && !mapping->a_ops->readpages))
		return -EINVAL;

	while (nr_to_read) {
		int err;

		unsigned long this_chunk = (2 * 1024 * 1024) / PAGE_CACHE_SIZE;

		if (this_chunk > nr_to_read)
			this_chunk = nr_to_read;
		err = __do_page_cache_readahead(mapping, filp,
						offset, this_chunk);
		if (err < 0) {
			ret = err;
			break;
		}
		ret += err;
		offset += this_chunk;
		nr_to_read -= this_chunk;
	}
	return ret;
}

/*
 * Check how effective readahead is being.  If the amount of started IO is
 * less than expected then the file is partly or fully in pagecache and
 * readahead isn't helping.
 *
 */
int check_ra_success(struct file_ra_state *ra, unsigned long nr_to_read,
				 unsigned long actual)
{
	if (actual == 0) {
		ra->cache_hit += nr_to_read;
		if (ra->cache_hit >= VM_MAX_CACHE_HIT) {
			ra_off(ra);
			ra->flags |= RA_FLAG_INCACHE;
			return 0;
		}
	} else {
		ra->cache_hit=0;
	}
	return 1;
}

/*
 * This version skips the IO if the queue is read-congested, and will tell the
 * block layer to abandon the readahead if request allocation would block.
 *
 * force_page_cache_readahead() will ignore queue congestion and will block on
 * request queues.
 */
int do_page_cache_readahead(struct address_space *mapping, struct file *filp,
			unsigned long offset, unsigned long nr_to_read)
{
	if (bdi_read_congested(mapping->backing_dev_info))
		return -1;

	return __do_page_cache_readahead(mapping, filp, offset, nr_to_read);
}

/*
 * Read 'nr_to_read' pages starting at page 'offset'. If the flag 'block'
 * is set wait till the read completes.  Otherwise attempt to read without
 * blocking.
 * Returns 1 meaning 'success' if read is succesfull without switching off
 * readhaead mode. Otherwise return failure.
 */
/**
 * ????
 */
static int
blockable_page_cache_readahead(struct address_space *mapping, struct file *filp,
			unsigned long offset, unsigned long nr_to_read,
			struct file_ra_state *ra, int block)
{
	int actual;

	if (block) {
		actual = __do_page_cache_readahead(mapping, filp,
						offset, nr_to_read);
	} else {
		actual = do_page_cache_readahead(mapping, filp,
						offset, nr_to_read);
		if (actual == -1)
			return 0;
	}
	return check_ra_success(ra, nr_to_read, actual);
}

/*
 * page_cache_readahead is the main function.  If performs the adaptive
 * readahead window size management and submits the readahead I/O.
 */
/**
 * ??????????????
 * ??????????????????????????????????????????????????????????????????????
 * mapping:		??????????????address_space????????????
 * ra:			??????????????file_ra_state????????????
 * filp:		??????????????
 * offset:		??????????????????
 * req_size:	????????????????????????????????
 */
unsigned long
page_cache_readahead(struct address_space *mapping, struct file_ra_state *ra,
		     struct file *filp, unsigned long offset,
		     unsigned long req_size)
{
	unsigned long max, min;
	unsigned long newsize = req_size;
	unsigned long block;

	/*
	 * Here we detect the case where the application is performing
	 * sub-page sized reads.  We avoid doing extra work and bogusly
	 * perturbing the readahead window expansion logic.
	 * If size is zero, there is no read ahead window so we need one
	 */
	if (offset == ra->prev_page && req_size == 1 && ra->size != 0)
		goto out;

	max = get_max_readahead(ra);
	min = get_min_readahead(ra);
	newsize = min(req_size, max);

	if (newsize == 0 || (ra->flags & RA_FLAG_INCACHE)) {
		newsize = 1;
		ra->prev_page = offset;
		goto out;	/* No readahead or file already in cache */
	}
	/*
	 * Special case - first read.  We'll assume it's a whole-file read if
	 * at start of file, and grow the window fast.  Or detect first
	 * sequential access
	 */
	if ((ra->size == 0 && offset == 0)	/* first io and start of file */
	    || (ra->size == -1 && ra->prev_page == offset - 1)) {
		/* First sequential */
		ra->prev_page  = offset + newsize - 1;
		ra->size = get_init_ra_size(newsize, max);
		ra->start = offset;
		if (!blockable_page_cache_readahead(mapping, filp, offset,
							 ra->size, ra, 1))
			goto out;

		/*
		 * If the request size is larger than our max readahead, we
		 * at least want to be sure that we get 2 IOs in flight and
		 * we know that we will definitly need the new I/O.
		 * once we do this, subsequent calls should be able to overlap
		 * IOs,* thus preventing stalls. so issue the ahead window
		 * immediately.
		 */
		if (req_size >= max) {
			ra->ahead_size = get_next_ra_size(ra->size, max, min,
							  &ra->flags);
			ra->ahead_start = ra->start + ra->size;
			blockable_page_cache_readahead(mapping, filp,
				 ra->ahead_start, ra->ahead_size, ra, 1);
		}
		goto out;
	}

	/*
	 * Now handle the random case:
	 * partial page reads and first access were handled above,
	 * so this must be the next page otherwise it is random
	 */
	if ((offset != (ra->prev_page+1) || (ra->size == 0))) {
		ra_off(ra);
		ra->prev_page  = offset + newsize - 1;
		blockable_page_cache_readahead(mapping, filp, offset,
				 newsize, ra, 1);
		goto out;
	}

	/*
	 * If we get here we are doing sequential IO and this was not the first
	 * occurence (ie we have an existing window)
	 */

	if (ra->ahead_start == 0) {	 /* no ahead window yet */
		ra->ahead_size = get_next_ra_size(ra->size, max, min,
						  &ra->flags);
		ra->ahead_start = ra->start + ra->size;
		block = ((offset + newsize -1) >= ra->ahead_start);
		if (!blockable_page_cache_readahead(mapping, filp,
		    ra->ahead_start, ra->ahead_size, ra, block)) {
			/* A read failure in blocking mode, implies pages are
			 * all cached. So we can safely assume we have taken
			 * care of all the pages requested in this call. A read
			 * failure in non-blocking mode, implies we are reading
			 * more pages than requested in this call.  So we safely
			 * assume we have taken care of all the pages requested
			 * in this call.
			 *
			 * Just reset the ahead window in case we failed due to
			 * congestion.  The ahead window will any way be closed
			 * in case we failed due to exessive page cache hits.
			 */
			ra->ahead_start = 0;
			ra->ahead_size = 0;
			goto out;
		}
	}
	/*
	 * Already have an ahead window, check if we crossed into it.
	 * If so, shift windows and issue a new ahead window.
	 * Only return the #pages that are in the current window, so that
	 * we get called back on the first page of the ahead window which
	 * will allow us to submit more IO.
	 */
	if ((offset + newsize - 1) >= ra->ahead_start) {
		ra->start = ra->ahead_start;
		ra->size = ra->ahead_size;
		ra->ahead_start = ra->ahead_start + ra->ahead_size;
		ra->ahead_size = get_next_ra_size(ra->ahead_size,
						  max, min, &ra->flags);
		block = ((offset + newsize - 1) >= ra->ahead_start);
		if (!blockable_page_cache_readahead(mapping, filp,
			ra->ahead_start, ra->ahead_size, ra, block)) {
			/* A read failure in blocking mode, implies pages are
			 * all cached. So we can safely assume we have taken
			 * care of all the pages requested in this call.
			 * A read failure in non-blocking mode, implies we are
			 * reading more pages than requested in this call.  So
			 * we safely assume we have taken care of all the pages
			 * requested in this call.
			 *
			 * Just reset the ahead window in case we failed due to
			 * congestion.  The ahead window will any way be closed
			 * in case we failed due to excessive page cache hits.
			 */
			ra->ahead_start = 0;
			ra->ahead_size = 0;
		}
	}

out:
	ra->prev_page = offset + newsize - 1;
	return(newsize);
}

/*
 * handle_ra_miss() is called when it is known that a page which should have
 * been present in the pagecache (we just did some readahead there) was in fact
 * not found.  This will happen if it was evicted by the VM (readahead
 * thrashing)
 *
 * Turn on the cache miss flag in the RA struct, this will cause the RA code
 * to reduce the RA size on the next read.
 */
void handle_ra_miss(struct address_space *mapping,
		struct file_ra_state *ra, pgoff_t offset)
{
	ra->flags |= RA_FLAG_MISS;
	ra->flags &= ~RA_FLAG_INCACHE;
}

/*
 * Given a desired number of PAGE_CACHE_SIZE readahead pages, return a
 * sensible upper limit.
 */
unsigned long max_sane_readahead(unsigned long nr)
{
	unsigned long active;
	unsigned long inactive;
	unsigned long free;

	__get_zone_counts(&active, &inactive, &free, NODE_DATA(numa_node_id()));
	return min(nr, (inactive + free) / 2);
}
