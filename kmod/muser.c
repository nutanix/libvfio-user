// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (c) 2019, Nutanix Inc. All rights reserved.
 *
 * Author: Thanos Makatos <thanos@nutanix.com>
 *         Swapnil Ingle <swapnil.ingle@nutanix.com>
 *         Felipe Franciosi <felipe@nutanix.com>
 *
 */

#include <linux/cdev.h>
#include <linux/compat.h>
#include <linux/device.h>
#include <linux/file.h>
#include <linux/idr.h>
#include <linux/list.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/stat.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/wait.h>
#include <linux/vfio.h>
#include <linux/mdev.h>
#include <linux/pagemap.h>
#include <asm-generic/mman-common.h>
#include <linux/device.h>
#include <linux/uaccess.h>

#include "muser.h"

#define DRIVER_NAME		"muser"

#define NR_PAGES(x)	(((x) + (PAGE_SIZE - 1)) >> PAGE_SHIFT)
#define MIN(a, b) ((a) < (b) ? (a):(b))

static struct muser {
	struct class *class;
	struct list_head dev_list;
	struct idr dev_idr;
	struct cdev muser_cdev;
	dev_t muser_devt;
	struct device dev;
	struct mutex muser_lock;
} muser;

#define muser_log(func, fmt, ...) \
		func(&muser.dev, "%s: " fmt "\n", __func__, ## __VA_ARGS__)

#define muser_dbg(fmt, ...)    muser_log(dev_dbg,   fmt, ## __VA_ARGS__)
#define muser_info(fmt, ...)   muser_log(dev_info,  fmt, ## __VA_ARGS__)
#define muser_warn(fmt, ...)   muser_log(dev_warn,  fmt, ## __VA_ARGS__)
#define muser_err(fmt, ...)    muser_log(dev_err,   fmt, ## __VA_ARGS__)
#define muser_alert(fmt, ...)  muser_log(dev_alert, fmt, ## __VA_ARGS__)

/* TODO come up with as better name? */
/*
 * FIXME len and nr_pages are confusing, we user either one or the other however
 * they seem to serve the same purpose, fix.
 */
struct page_map {
	struct page **pages;
	int nr_pages;
	size_t len;
	int offset;
};

struct vfio_dma_mapping {
	unsigned long		iova;
	unsigned long		length;
	struct page		**pages;
	struct list_head	entry;
};

/*
 * TODO do we use all members at the same time? Does it make sense to put some
 * of them in a union?
 */
struct mudev_cmd {
	enum muser_cmd_type type;	/* copy of muser_cmd.type */
	struct muser_cmd muser_cmd;
	struct page_map pg_map;
	struct file **fds;
	int *data_fds;
	/*
	 * When libmuser completes an mmap call, we need to know the length
	 * in order to pass it to do_pin_pages.
	 */
	unsigned long mmap_len;
	struct list_head entry;
};

// FIXME: Reorganise the members of this struct.
struct muser_dev {
	guid_t uuid;
	int minor;
	struct device *dev;
	struct list_head dlist_entry;
	struct list_head cmd_list;
	// FIXME: mucmd_pending should be per filep context.
	struct mudev_cmd *mucmd_pending;
	// FIXME: muser_dev should have a list of filep contexts instead of
	// srv_opened
	atomic_t srv_opened;
	atomic_t mdev_opened;
	struct mutex dev_lock;
	struct mdev_device *mdev;
	wait_queue_head_t user_wait_q;
	struct semaphore sem;
	struct notifier_block iommu_notifier;

	struct vfio_dma_mapping *dma_map;	/* Current DMA operation */
	struct list_head dma_list;		/* list of dma mappings */

	struct radix_tree_root devmem_tree;	/* Device memory */
};

/* function prototypes */
static int dma_unmap_all(struct muser_dev *const mudev, const bool skip_user);

static inline int muser_copyout(void __user *param, const void *address,
				unsigned long size)
{
	int err = copy_to_user(param, address, size) ? -EFAULT : 0;

	if (unlikely(err))
		muser_dbg("failed to copy to user: %d", err);

	return err;
}

static inline int muser_copyin(void *address, void __user *param,
			       unsigned long size)
{
	int err = copy_from_user(address, param, size) ? -EFAULT : 0;

	if (unlikely(err))
		muser_dbg("failed to copy from user: %d", err);

	return err;
}

/* called with muser.muser_lock held */
static struct muser_dev *__muser_search_dev(const guid_t *uuid)
{
	struct muser_dev *mudev;

	list_for_each_entry(mudev, &muser.dev_list, dlist_entry) {
		const uuid_le *u = &mudev->uuid;

		if (uuid_le_cmp(*u, *uuid) == 0)
			return mudev;
	}

	return NULL;
}

static int muser_create_dev(const guid_t *uuid, struct mdev_device *mdev)
{
	struct muser_dev *mudev;
	char uuid_str[UUID_STRING_LEN + 1];
	int minor;
	int err = 0;

	mutex_lock(&muser.muser_lock);
	mudev = __muser_search_dev(uuid);
	if (mudev) {
		err = -EEXIST;
		goto out;
	}

	mudev = kzalloc(sizeof(*mudev), GFP_KERNEL);
	if (!mudev) {
		err = -ENOMEM;
		goto out;
	}

	minor = idr_alloc(&muser.dev_idr, mudev, 0, MINORMASK + 1, GFP_KERNEL);
	if (minor < 0) {
		err = minor;
		kfree(mudev);
		goto out;
	}

	sprintf(uuid_str, "%pUl", uuid);
	mudev->dev = device_create(muser.class, NULL,
				   MKDEV(MAJOR(muser.muser_devt), minor),
				   mudev, "%s", uuid_str);
	if (IS_ERR(mudev->dev)) {
		err = PTR_ERR(mudev->dev);
		idr_remove(&muser.dev_idr, minor);
		kfree(mudev);
		goto out;
	}

	memcpy(&mudev->uuid, uuid, sizeof(mudev->uuid));
	mudev->minor = minor;
	mudev->mdev = mdev;
	mutex_init(&mudev->dev_lock);
	sema_init(&mudev->sem, 0);
	init_waitqueue_head(&mudev->user_wait_q);
	INIT_LIST_HEAD(&mudev->cmd_list);
	INIT_LIST_HEAD(&mudev->dma_list);
	INIT_RADIX_TREE(&mudev->devmem_tree, GFP_KERNEL);
	list_add(&mudev->dlist_entry, &muser.dev_list);
	mdev_set_drvdata(mdev, mudev);

	muser_info("new device %s", uuid_str);

out:
	mutex_unlock(&muser.muser_lock);
	return err;
}

/* called with muser.muser_lock held */
static void __muser_deinit_dev(struct muser_dev *mudev)
{
	device_destroy(muser.class,
		       MKDEV(MAJOR(muser.muser_devt), mudev->minor));
	list_del(&mudev->dlist_entry);
	idr_remove(&muser.dev_idr, mudev->minor);
}

/* called with mudev.dev_lock held */
static void __mudev_page_free(struct muser_dev *mudev, unsigned long pgnr)
{
	struct page *pg;

	pg = radix_tree_delete(&mudev->devmem_tree, pgnr);
	if (WARN_ON(!pg))
		return;

	__free_page(pg);
}

#define NR_INDICES	16

/* called with mudev.dev_lock held */
static void __mudev_free_devmem(struct muser_dev *mudev)
{
	struct radix_tree_iter iter;
	struct radix_tree_root *root = &mudev->devmem_tree;
	unsigned long indices[NR_INDICES], index = 0;
	void __rcu **slot;
	int i, nr;

	do {
		nr = 0;
		radix_tree_for_each_slot(slot, root, &iter, index) {
			indices[nr] = iter.index;
			if (++nr == NR_INDICES)
				break;
		}
		for (i = 0; i < nr; i++) {
			index = indices[i];
			__mudev_page_free(mudev, index);
		}
	} while (nr > 0);
}

static int muser_remove_dev(const uuid_le *uuid)
{
	struct muser_dev *mudev;
	char uuid_str[UUID_STRING_LEN + 1];
	int err = 0;

	mutex_lock(&muser.muser_lock);

	mudev = __muser_search_dev(uuid);
	if (!mudev) {
		err = -ENOENT;
		goto out;
	}

	if (atomic_read(&mudev->mdev_opened) > 0 ||
	    atomic_read(&mudev->srv_opened) > 0) {
		err = -EBUSY;
		goto out;
	}

	mutex_lock(&mudev->dev_lock);

	WARN_ON(!list_empty(&mudev->cmd_list));
	__mudev_free_devmem(mudev);
	__muser_deinit_dev(mudev);

	mutex_unlock(&mudev->dev_lock);
	kfree(mudev);

	sprintf(uuid_str, "%pUl", uuid);
	muser_info("removed muser device %s", uuid_str);

out:
	mutex_unlock(&muser.muser_lock);
	return err;
}

static ssize_t name_show(struct kobject *kobj, struct device *dev, char *buf)
{
	return sprintf(buf, "muser\n");
}

MDEV_TYPE_ATTR_RO(name);

static ssize_t device_api_show(struct kobject *kobj, struct device *dev,
			       char *buf)
{
	return sprintf(buf, "%s\n", VFIO_DEVICE_API_PCI_STRING);
}

MDEV_TYPE_ATTR_RO(device_api);

static struct attribute *mdev_types_attrs[] = {
	&mdev_type_attr_name.attr,
	&mdev_type_attr_device_api.attr,
	NULL,
};

static struct attribute_group mdev_type_group = {
	.name = "1",
	.attrs = mdev_types_attrs,
};

struct attribute_group *mdev_type_groups[] = {
	&mdev_type_group,
	NULL,
};

static int muser_process_cmd(struct muser_dev *mudev, struct mudev_cmd *mucmd)
{
	int err;

	mucmd->type = mucmd->muser_cmd.type;

	/* Add command to mudev list of commands. */
	mutex_lock(&mudev->dev_lock);
	list_add_tail(&mucmd->entry, &mudev->cmd_list);
	mutex_unlock(&mudev->dev_lock);

	/* Wake up any sleepers */
	wake_up(&mudev->user_wait_q);

	/*
	 * TODO: decide what to do with timeouts
	 * Timeouts can happen if:
	 * 1. No server has attached to mudev
	 * 2. Processing of cmd takes more time than timeout
	 */
	/*
	 * TODO: Maybe use a while loop instead of goto
	 */
retry:
	err = down_timeout(&mudev->sem, msecs_to_jiffies(5000));
	if (err) {
		struct mudev_cmd *pos, *tmp;
		bool found = false;

		mutex_lock(&mudev->dev_lock);
		list_for_each_entry_safe(pos, tmp, &mudev->cmd_list, entry) {
			if (pos == mucmd) {
				list_del(&mucmd->entry);
				found = true;
				break;
			}
		}
		mutex_unlock(&mudev->dev_lock);
		if (found) {
			muser_err("giving up, no response for cmd %d",
				  mucmd->type);
		} else {
			muser_warn("server taking too long for cmd %d, retry",
				   mucmd->type);
			goto retry;
		}
	}

	return err;
}

int muser_create(struct kobject *kobj, struct mdev_device *mdev)
{
	const guid_t *uuid = mdev_uuid(mdev);

	return muser_create_dev(uuid, mdev);
}

int muser_remove(struct mdev_device *mdev)
{
	const guid_t *uuid = mdev_uuid(mdev);

	return muser_remove_dev(uuid);
}

static int do_pin_pages(char __user *buf, const size_t count,
			int const writeable, struct page_map *const pg_map)
{
	unsigned long start;
	unsigned long __user lbuf = (unsigned long __user)buf;
	int i;
	int err;

	BUG_ON(!buf);
	BUG_ON(!pg_map);

	start = round_down(lbuf, PAGE_SIZE);
	pg_map->nr_pages = (round_up(lbuf + count, PAGE_SIZE) - start) /
			   PAGE_SIZE;
	pg_map->offset = lbuf - start;
	pg_map->pages = kcalloc(pg_map->nr_pages, sizeof *(pg_map->pages),
				GFP_KERNEL);
	if (unlikely(!pg_map->pages)) {
		muser_dbg("failed to allocate %d pages", pg_map->nr_pages);
		return -ENOMEM;
	}
	err = get_user_pages_fast(start, pg_map->nr_pages, writeable,
				  pg_map->pages);
	if (unlikely(err != pg_map->nr_pages)) {
		for (i = 0; i < err; i++)
			put_page(pg_map->pages[i]);
		kfree(pg_map->pages);
		muser_dbg("failed to get user pages: %d", err);
		return -ENOMEM;
	}

	return 0;
}

static void unpin_pages(struct page_map *const pg_map)
{
	int i;

	if (!pg_map)
		return;

	for (i = 0; i < pg_map->nr_pages; i++)
		put_page(pg_map->pages[i]);
	kfree(pg_map->pages);
	pg_map->pages = NULL;
}


static int vm_insert_pages(struct vm_area_struct *const vma,
			   struct page *const pages[], const int nr_pages)
{
	int err = 0, i;

	for (i = 0; i < nr_pages; i++) {
		BUG_ON(!pages[i]);
		err = vm_insert_page(vma, vma->vm_start + i * PAGE_SIZE,
				     pages[i]);
		if (unlikely(err)) {
			muser_dbg("count=%d, anon=%d, slab=%d, type=%d",
				  page_count(pages[i]), PageAnon(pages[i]),
				  PageSlab(pages[i]), page_has_type(pages[i]));
			muser_dbg("failed to insert page at %lx: %d",
				  vma->vm_start + i * PAGE_SIZE, err);
			unmap_kernel_range((unsigned long)vma->vm_start,
					   PAGE_SIZE);
			break;
		}
	}
	return err;
}

static struct page *mudev_page_alloc(struct muser_dev *mudev,
				     unsigned long pgnr)
{
	struct page *pg;
	int ret;

	pg = alloc_page(GFP_KERNEL);
	if (unlikely(!pg))
		return NULL;

	ret = radix_tree_insert(&mudev->devmem_tree, pgnr, pg);
	if (ret) {
		__free_page(pg);
		return NULL;
	}

	return pg;
}

static int libmuser_mmap_dev(struct file *fp, struct vm_area_struct *vma)
{
	struct muser_dev *mudev = fp->private_data;
	struct page *pg;
	unsigned int nr_pages;
	unsigned long cur_pgidx, end_pgidx;
	unsigned long addr, *new_pgs;
	int ret, i;

	WARN_ON(mudev == NULL);
	nr_pages = (vma->vm_end - vma->vm_start) >> PAGE_SHIFT;

	/* array to track new allocated pages, to be free'd
	 * in case of failure */
	new_pgs = kmalloc(nr_pages * sizeof(*new_pgs), GFP_KERNEL);
	if (!new_pgs)
		return -ENOMEM;

	cur_pgidx = vma->vm_pgoff & ~(BIT(63 - PAGE_SHIFT));
	end_pgidx = cur_pgidx + nr_pages;

	muser_info("mmap_dev: end 0x%lX - start 0x%lX (%lX), off = 0x%lX",
		   vma->vm_end, vma->vm_start, vma->vm_end - vma->vm_start,
		   cur_pgidx);

	mutex_lock(&mudev->dev_lock);
	for (i = 0; cur_pgidx < end_pgidx; cur_pgidx++, i++) {
		pg = radix_tree_lookup(&mudev->devmem_tree, cur_pgidx);
		if (!pg) {
			pg = mudev_page_alloc(mudev, cur_pgidx);
			if (!pg) {
				i--;
				ret = -ENOMEM;
				goto free_pg;
			}
		}

		addr = vma->vm_start + (cur_pgidx << PAGE_SHIFT);
		ret = vm_insert_page(vma, addr, pg);
		if (unlikely(ret))
			goto free_pg;
	}

	mutex_unlock(&mudev->dev_lock);
	kfree(new_pgs);
	return 0;

free_pg:
	for ( ;i >= 0; i--)
		__mudev_page_free(mudev, new_pgs[i]);
	mutex_unlock(&mudev->dev_lock);
	kfree(new_pgs);
	return ret;
}

static int libmuser_mmap_dma(struct file *f, struct vm_area_struct *vma)
{
	int err;
	unsigned long length;
	struct vfio_dma_mapping *dma_map;
	struct muser_dev *mudev = f->private_data;

	BUG_ON(!mudev);

	muser_info("mmap_dma: end 0x%lX - start 0x%lX (%lX), off = 0x%lX",
		   vma->vm_end, vma->vm_start, vma->vm_end - vma->vm_start,
		   vma->vm_pgoff);

	if (unlikely(!mudev->dma_map)) {
		muser_dbg("no pending DMA map operation");
		return -EINVAL;
	}

	dma_map = mudev->dma_map;
	length = round_up(dma_map->length, PAGE_SIZE);
	if (unlikely(vma->vm_end - vma->vm_start != length)) {
		muser_dbg("expected mmap of %lx bytes, got %lx instead",
			  vma->vm_end - vma->vm_start, length);
		return -EINVAL;
	}

	err = vm_insert_pages(vma, dma_map->pages, NR_PAGES(dma_map->length));
	if (unlikely(err)) {
		muser_dbg("DMA region insert failed (%lu pages: %lx-%lx): %d",
			  NR_PAGES(dma_map->length), vma->vm_start,
			  vma->vm_end, err);
		return err;
	}

	return 0;
}

static int libmuser_mmap(struct file *f, struct vm_area_struct *vma)
{
	if (vma->vm_pgoff & BIT(63 - PAGE_SHIFT)) {
		muser_info("offset: 0x%lX (top bit set)", vma->vm_pgoff);
		return libmuser_mmap_dev(f, vma);
	}

	muser_dbg("offset: 0x%lX", vma->vm_pgoff);
	return libmuser_mmap_dma(f, vma);
}

static int muser_process_dma_request(struct muser_dev *mudev,
				     struct vfio_dma_mapping *dma_map,
				     int flags, int type)
{
	int err;
	struct mudev_cmd mucmd = {
		.type = type,
		.muser_cmd = {
			.type = type,
			.mmap = {
				.request = {
					.start = dma_map->iova,
					.end = dma_map->iova + dma_map->length,
					.flags = flags}
			}
		}
	};

	err = muser_process_cmd(mudev, &mucmd);
	if (unlikely(err))
		return err;

	return mucmd.muser_cmd.mmap.response.addr;
}

static int muser_process_dma_map(struct muser_dev *mudev, int flags)
{
	return muser_process_dma_request(mudev, mudev->dma_map, flags,
					 MUSER_DMA_MMAP);
}

static int muser_process_dma_unmap(struct muser_dev *mudev,
				   struct vfio_dma_mapping *dma_map)
{
	return muser_process_dma_request(mudev, dma_map, 0, MUSER_DMA_MUNMAP);
}

static int put_dma_map(struct muser_dev *mudev,
			 struct vfio_dma_mapping *dma_map, int nr_pages)
{
	unsigned long off, iova_pfn;
	int i, ret;

	for (i = 0, off = 0; i < nr_pages; i++, off += PAGE_SIZE) {
		iova_pfn = (dma_map->iova + off) >> PAGE_SHIFT;
		ret = vfio_unpin_pages(mdev_dev(mudev->mdev), &iova_pfn, 1);
		if (WARN_ON(ret != 1))
			return -EINVAL;

		put_page(dma_map->pages[i]);
	}

	kfree(dma_map->pages);
	return 0;
}

static int
get_dma_map(struct muser_dev *mudev, struct vfio_dma_mapping *dma_map,
	    struct vfio_iommu_type1_dma_map *map)
{
	unsigned long iova, vaddr;
	unsigned long iova_pfn, phys_pfn;
	unsigned long length, off;
	int pgflag, ret, nr_pages = 0;
	struct page **pages;

	length = map->size;
	pages = kmalloc_array(NR_PAGES(length), sizeof(*pages), GFP_KERNEL);
	if (!pages)
		return -ENOMEM;

	pgflag = map->flags & VFIO_DMA_MAP_FLAG_WRITE ? FOLL_WRITE : 0;
	dma_map->pages = pages;
	dma_map->iova = map->iova;
	dma_map->length = map->size;

	iova = map->iova;
	vaddr = map->vaddr;

	/*
	 * XXX: for now the for loop is for each page, vfio_pin_pages() has
	 * limit of 512 pages.
	 */
	for (off = 0; off < length; off += PAGE_SIZE, vaddr += PAGE_SIZE) {
		iova_pfn = (iova + off) >> PAGE_SHIFT;
		ret = vfio_pin_pages(mdev_dev(mudev->mdev), &iova_pfn, 1,
				     map->flags, &phys_pfn);
		if (ret != 1)
			goto err;

		ret = get_user_pages_fast(vaddr, 1, pgflag, pages + nr_pages);
		if (ret != 1) {
			vfio_unpin_pages(mdev_dev(mudev->mdev), &iova_pfn, 1);
			goto err;
		}

		nr_pages++;
	}

	return 0;

err:
	put_dma_map(mudev, dma_map, nr_pages);
	return ret;
}

static int has_anonymous_pages(struct vfio_dma_mapping *dma_map)
{
	int i, nr_pages = NR_PAGES(dma_map->length);

	for (i = 0; i < nr_pages; i++) {
		if (PageAnon(dma_map->pages[i])) {
			muser_dbg("ignore IOVA=%lx, page(s) not shared",
				  dma_map->iova);
			return 1;
		}
	}

	return 0;
}

static int muser_iommu_dma_map(struct muser_dev *mudev,
				struct vfio_iommu_type1_dma_map *map)
{
	struct vfio_dma_mapping *dma_map;
	int ret;

	/* TODO: support multiple DMA map operations in parallel */
	mutex_lock(&mudev->dev_lock);
	if (mudev->dma_map) {
		mutex_unlock(&mudev->dev_lock);
		muser_dbg("another DMA map operation is ongoing");
		return -EBUSY;
	}

	dma_map = kmalloc(sizeof(struct vfio_dma_mapping), GFP_KERNEL);
	if (!dma_map) {
		mutex_unlock(&mudev->dev_lock);
		return -ENOMEM;
	}
	mudev->dma_map = dma_map;
	mutex_unlock(&mudev->dev_lock);

	/* get vfio client pages to be used for DMA map */
	ret = get_dma_map(mudev, dma_map, map);
	if (ret)
		goto out;

	/* skip anonymous pages */
	if (has_anonymous_pages(mudev->dma_map))
		goto put_pages;

	ret = muser_process_dma_map(mudev, map->flags);
	if (ret)
		goto put_pages;

	/* add to the dma_list */
	mutex_lock(&mudev->dev_lock);
	list_add_tail(&dma_map->entry, &mudev->dma_list);
	mudev->dma_map = NULL;
	mutex_unlock(&mudev->dev_lock);
	return 0;

put_pages:
	put_dma_map(mudev, dma_map, NR_PAGES(dma_map->length));

out:
	kfree(dma_map);
	mutex_lock(&mudev->dev_lock);
	mudev->dma_map = NULL;
	mutex_unlock(&mudev->dev_lock);
	return ret;
}

/* called with mudev.dev_lock held */
static struct vfio_dma_mapping *__find_dma_map(struct muser_dev *mudev,
					       unsigned long iova)
{
	struct vfio_dma_mapping *dma_map;

	list_for_each_entry(dma_map, &mudev->dma_list, entry) {
		if (dma_map->iova == iova)
			return dma_map;
	}
	return NULL;
}

static int muser_iommu_dma_unmap(struct muser_dev *const mudev,
		struct vfio_iommu_type1_dma_unmap *const unmap)
{
	int err;
	int len;
	struct vfio_dma_mapping *dma_map;

	mutex_lock(&mudev->dev_lock);
	dma_map = __find_dma_map(mudev, unmap->iova);
	if (!dma_map) {
		mutex_unlock(&mudev->dev_lock);
		muser_dbg("failed to find dma map for iova:%llu\n", unmap->iova);
		return -EINVAL;
	}
	list_del(&dma_map->entry);
	mutex_unlock(&mudev->dev_lock);

	len = dma_map->length;
	err = muser_process_dma_unmap(mudev, dma_map);
	if (unlikely(err))
		muser_dbg("failed to request PCI server to munmap: %d", err);

	err = put_dma_map(mudev, dma_map, NR_PAGES(len));
	if (unlikely(err)) {
		muser_dbg("failed to tear down DMA map: %d", err);
		goto out;
	}

	/* XXX: Do we need this? */
	unmap->size = len;
out:
	return err;
}

/*
 * FIXME There can be multiple DMA map calls per device. If each of these calls
 * are serialised (this can be enforced by muser), then we tell PCI server to
 * mmap the control device. Do we need to distinguish between the different
 * DMA map calls at this stage if we can enforce only one outstanding DMA map
 * call? What happens when the DMA map happens too early, before GET_DEVICE_FD
 * is called?
 */
static int muser_iommu_notifier(struct notifier_block *nb, unsigned long action,
		void *data)
{
	struct muser_dev *mudev;
	int err;

	BUG_ON(!nb);
	BUG_ON(!data);

	mudev = container_of(nb, struct muser_dev, iommu_notifier);
	switch (action) {
	case VFIO_IOMMU_NOTIFY_DMA_MAP:
		err = muser_iommu_dma_map(mudev,
					  (struct vfio_iommu_type1_dma_map *)
					  data);
		break;
	case VFIO_IOMMU_NOTIFY_DMA_UNMAP:
		err = muser_iommu_dma_unmap(mudev,
					    (struct vfio_iommu_type1_dma_unmap
					     *)data);
		break;
	default:
		muser_dbg("bad action=%lx", action);
		err = -EINVAL;
	}

	if (unlikely(err))
		return NOTIFY_BAD;
	return NOTIFY_OK;
}

static int register_notifier(struct mdev_device *const mdev)
{
	unsigned long events =
	    VFIO_IOMMU_NOTIFY_DMA_MAP | VFIO_IOMMU_NOTIFY_DMA_UNMAP;
	struct muser_dev *const mudev = mdev_get_drvdata(mdev);

	memset(&mudev->iommu_notifier, 0, sizeof(mudev->iommu_notifier));
	mudev->iommu_notifier.notifier_call = muser_iommu_notifier;
	return vfio_register_notifier(mdev_dev(mdev), VFIO_IOMMU_NOTIFY,
				      &events, &mudev->iommu_notifier);
}

int muser_open(struct mdev_device *mdev)
{
	int err;
	struct muser_dev *mudev = mdev_get_drvdata(mdev);

	WARN_ON(mudev == NULL);

	if (atomic_cmpxchg(&mudev->mdev_opened, 0, 1) != 0) {
		muser_dbg("device already open");
		return -EBUSY;
	}

	err = register_notifier(mdev);
	if (unlikely(err)) {
		int err2;
		/*
		 * TODO we might have triggered some notifiers which will have
		 * caused PCI server to mmap. If open fails then PCI server dies
		 * therefore things get automatically cleaned up (e.g.
		 * vfio_unpin etc.)?
		 */
		atomic_dec(&mudev->mdev_opened);
		muser_dbg("failed to register notifier: %d", err);
		err2 = dma_unmap_all(mudev, false);
		if (unlikely(err2))
			muser_dbg("failed to DMA unmap all regions: %d",
					err2);
		err2 =
		    vfio_unregister_notifier(mdev_dev(mdev), VFIO_IOMMU_NOTIFY,
					     &mudev->iommu_notifier);
		if (unlikely(err2))
			muser_info("failed to unregister notifier: %d", err);

	}

	return err;
}

static int dma_unmap_all(struct muser_dev *mudev, bool skip_user)
{
	struct vfio_dma_mapping *dma_map;
	unsigned long length;
	LIST_HEAD(head);

	mutex_lock(&mudev->dev_lock);
	while (!list_empty(&mudev->dma_list)) {
		dma_map = list_first_entry(&mudev->dma_list,
					     struct vfio_dma_mapping, entry);
		list_move(&dma_map->entry, &head);
	}
	mutex_unlock(&mudev->dev_lock);

	while (!list_empty(&head)) {
		int err;

		dma_map = list_first_entry(&head, struct vfio_dma_mapping,
					     entry);
		list_del(&dma_map->entry);
		if (!skip_user) {
			err = muser_process_dma_unmap(mudev, dma_map);
			if (unlikely(err)) {
				muser_alert("unmap request failed IOVA=%lx: %d",
					    dma_map->iova, err);
				continue;
			}
		}

		length = dma_map->length;
		err = put_dma_map(mudev, dma_map, NR_PAGES(length));
		if (unlikely(err))
			muser_alert("failed to unmap DMA IOVA=%lx: %d",
				    dma_map->iova, err);
	}
	return 0;
}

void muser_close(struct mdev_device *mdev)
{
	struct muser_dev *mudev = mdev_get_drvdata(mdev);
	int err;

	err = dma_unmap_all(mudev, false);
	if (unlikely(err))
		muser_alert("failed to remove one or more DMA maps");

	err = vfio_unregister_notifier(mdev_dev(mdev), VFIO_IOMMU_NOTIFY,
				       &mudev->iommu_notifier);
	if (unlikely(err))
		muser_info("failed to unregister notifier: %d", err);

	WARN_ON(atomic_read(&mudev->mdev_opened) == 0);
	atomic_dec(&mudev->mdev_opened);

	/* TODO: Replace any pending mucmd back in cmd_list. */
}

static int
pin_pages(struct mudev_cmd *mucmd, char __user *buf, size_t count,
	  int writeable)
{
	mucmd->pg_map.len = count;
	return do_pin_pages(buf, count, writeable, &mucmd->pg_map);
}

void dump_buffer(unsigned char const *const buf, uint32_t count)
{
#if defined(DEBUG)
	print_hex_dump(KERN_INFO, "", DUMP_PREFIX_NONE, 4, 1, buf, count,
		       false);
#endif
}

ssize_t muser_read(struct mdev_device *mdev, char __user *buf, size_t count,
		loff_t *ppos)
{
	struct muser_dev *mudev = mdev_get_drvdata(mdev);
	struct mudev_cmd mucmd = { 0 };
	int err;

	WARN_ON(mudev == NULL);

	/* Setup mucmd and ping pages of the calling context. */
	mucmd.type = MUSER_READ;
	err = pin_pages(&mucmd, buf, count, 1);
	if (err != 0)
		return err;

	/* Setup muser_cmd for server context. */
	mucmd.muser_cmd.type = MUSER_READ;
	mucmd.muser_cmd.rw.count = count;
	mucmd.muser_cmd.rw.pos = *ppos;

	muser_dbg("R %lx@%llx", mucmd.muser_cmd.rw.count,
		  mucmd.muser_cmd.rw.pos);

	/* Process mudev_cmd in libmuser context. */
	err = muser_process_cmd(mudev, &mucmd);
	if (err != 0)
		count = -1;
	*ppos = mucmd.muser_cmd.rw.pos;

	unpin_pages(&mucmd.pg_map);

	dump_buffer(buf, count);
	return count;
}

ssize_t muser_write(struct mdev_device *mdev, const char __user *buf,
		size_t count, loff_t *ppos)
{
	struct muser_dev *mudev = mdev_get_drvdata(mdev);
	struct mudev_cmd mucmd = { 0 };
	int err;
	size_t _count = count;
	loff_t _pos = *ppos;

	muser_dbg("W %lx@%llx", count, *ppos);
	dump_buffer(buf, count);

	/* Setup mucmd and pin pages of the calling context. */
	mucmd.type = MUSER_WRITE;
	err = pin_pages(&mucmd, (char __user *)buf, count, 0);
	if (err != 0)
		return err;

	/* Setup muser_cmd for libmuser context. */
	mucmd.muser_cmd.type = MUSER_WRITE;
	mucmd.muser_cmd.rw.count = count;
	mucmd.muser_cmd.rw.pos = *ppos;

	/* Process mudev_cmd in server context. */
	err = muser_process_cmd(mudev, &mucmd);
	if (err != 0)
		count = -1;
	*ppos = mucmd.muser_cmd.rw.pos;

	unpin_pages(&mucmd.pg_map);

	if (mucmd.muser_cmd.err)
		muser_info("PCI config write %ld@0x%llx not handled: %d",
			_count, _pos, mucmd.muser_cmd.err);

	return count;
}

static int
bounce_fds(struct mudev_cmd *mucmd, void __user *data, int user_data_size)
{
	int count = mucmd->muser_cmd.ioctl.data.irq_set.count;
	int data_size = count * sizeof(int32_t);
	int *user_fds;
	int i;
	int ret = 0;

	if (user_data_size < data_size)
		return -EINVAL;

	mucmd->fds = kcalloc(count, sizeof(*mucmd->fds), GFP_KERNEL);
	if (mucmd->fds == NULL)
		return -ENOMEM;

	user_fds = memdup_user(data, data_size);
	if (IS_ERR(user_fds)) {
		kfree(mucmd->fds);
		mucmd->fds = NULL;
		return PTR_ERR(user_fds);
	}

	for (i = 0; i < count; i++) {
		if (user_fds[i] == -1)
			continue;
		mucmd->fds[i] = fget(user_fds[i]);
		if (mucmd->fds[i] == NULL) {
			ret = -EBADF;
			goto err;
		}
	}

	kfree(user_fds);

	return 0;

err:
	for (i--; i >= 0; i--)
		fput(mucmd->fds[i]);
	kfree(user_fds);
	kfree(mucmd->fds);
	mucmd->fds = NULL;

	return ret;
}

static unsigned int get_minsz(unsigned int cmd)
{
	switch (cmd) {
	case VFIO_DEVICE_GET_INFO:
		return offsetofend(struct vfio_device_info, num_irqs);
	case VFIO_DEVICE_GET_REGION_INFO:
		return offsetofend(struct vfio_region_info, offset);
	case VFIO_DEVICE_GET_IRQ_INFO:
		return offsetofend(struct vfio_irq_info, count);
	case VFIO_DEVICE_SET_IRQS:
		return offsetofend(struct vfio_irq_set, count);
	}
	return -1;
}

static unsigned int get_argsz(unsigned int cmd, struct mudev_cmd *mucmd)
{
	switch (cmd) {
	case VFIO_DEVICE_GET_INFO:
		return mucmd->muser_cmd.ioctl.data.dev_info.argsz;
	case VFIO_DEVICE_GET_REGION_INFO:
		return mucmd->muser_cmd.ioctl.data.reg_info.argsz;
	case VFIO_DEVICE_GET_IRQ_INFO:
		return mucmd->muser_cmd.ioctl.data.irq_info.argsz;
	case VFIO_DEVICE_SET_IRQS:
		return mucmd->muser_cmd.ioctl.data.irq_set.argsz;
	}
	return -1;
}

static int muser_ioctl_setup_cmd(struct mudev_cmd *mucmd, unsigned int cmd,
			     unsigned long arg)
{
	unsigned int minsz;
	unsigned int argsz;
	int err;

	/* Determine smallest argsz we need for this command. */
	minsz = get_minsz(cmd);
	if (minsz == -1)
		return -EOPNOTSUPP;

	/* Copy caller-provided arg. */
	err = muser_copyin(&mucmd->muser_cmd.ioctl.data, (void __user *)arg,
			   minsz);
	if (unlikely(err))
		return err;

	/* Fetch argsz provided by caller. */
	argsz = get_argsz(cmd, mucmd);
	if (argsz == -1)
		return -EINVAL;

	/* Ensure provided size is at least the minimum required. */
	if (argsz < minsz)
		return -EINVAL;

	/* Fetch potential data provided on SET_IRQS. */
	if (cmd == VFIO_DEVICE_SET_IRQS) {
		unsigned int flags = mucmd->muser_cmd.ioctl.data.irq_set.flags;

		switch ((flags & VFIO_IRQ_SET_DATA_TYPE_MASK)) {
		case VFIO_IRQ_SET_DATA_EVENTFD:
			/* Lookup eventfds and bounce references to mucmd. */
			err = bounce_fds(mucmd, (void __user *) (arg + minsz),
					 argsz - minsz);
			if (err) {
				muser_dbg("failed to bounce fds: %d\n", err);
				return err;
			}
			break;
		}
	}

	/* Pin pages of the calling context. */
	err = pin_pages(mucmd, (char __user *)arg, argsz, 1);
	if (unlikely(err)) {
		muser_dbg("failed to pin pages: %d\n", err);
		return err;
	}

	return err;
}

static long muser_ioctl(struct mdev_device *mdev, unsigned int cmd,
			unsigned long arg)
{
	struct muser_dev *mudev = mdev_get_drvdata(mdev);
	struct mudev_cmd mucmd = { 0 };
	int err;

	muser_dbg("mdev=%p, cmd=%u, arg=0x%lX\n", mdev, cmd, arg);

	if (cmd == VFIO_DEVICE_RESET) {
		/*
		 * Qemu-vfio(check vfio_pci_reset()) takes care of
		 * enabling/disabling Interrupts.
		 *
		 * FIXME:
		 * No need to block pci config access as only one
		 * mdev_parent_ops is allowed to execute at a time.
		 *
		 * Returning -EAGAIN if client tries to send multiple resets.
		 */
		if (!device_trylock(mudev->dev))
			return -EAGAIN;
	} else {
		err = muser_ioctl_setup_cmd(&mucmd, cmd, arg);
		if (err)
			return err;
	}

	/* Setup common mucmd records. */
	mucmd.type = MUSER_IOCTL;
	mucmd.muser_cmd.type = MUSER_IOCTL;
	mucmd.muser_cmd.ioctl.vfio_cmd = cmd;

	/* Process mudev_cmd in server context. */
	err = muser_process_cmd(mudev, &mucmd);
	if (err != 0) {
		muser_dbg("failed to process command: %d\n", err);
		err = -1;
	}

	if (cmd == VFIO_DEVICE_RESET) {
		device_unlock(mudev->dev);
	} else {
		/* Release resources. */
		unpin_pages(&mucmd.pg_map);

		/* maybe allocated for VFIO_IRQ_SET_DATA_EVENTFD */
		kfree(mucmd.fds);
		kfree(mucmd.data_fds);
	}

	return err;
}

static int muser_mmap(struct mdev_device *const mdev,
		      struct vm_area_struct *const vma)
{
	struct muser_dev *mudev = mdev_get_drvdata(mdev);
	struct mudev_cmd mucmd = { 0 };
	int err;

	BUG_ON(!mudev);
	BUG_ON(!vma);

	/*
	 * Checking vm_flags cannot be easily done in user space as we can't
	 * access mm.h, so we have to do it here. Maybe implement the reverse
	 * of calc_vm_prot_bits/calc_vm_flag_bits?
	 */
	if ((vma->vm_flags & ~(VM_READ | VM_WRITE | VM_SHARED | VM_MAYREAD |
			       VM_MAYWRITE | VM_MAYEXEC | VM_MAYSHARE))) {
		muser_dbg("bag flags=0x%lx", vma->vm_flags);
		return -EINVAL;
	}

	mucmd.type = MUSER_MMAP;
	mucmd.muser_cmd.type = MUSER_MMAP;
	mucmd.muser_cmd.mmap.request.start = vma->vm_start;
	mucmd.muser_cmd.mmap.request.end = vma->vm_end;
	mucmd.muser_cmd.mmap.request.pgoff = vma->vm_pgoff;
	mucmd.mmap_len = vma->vm_end - vma->vm_start;

	/* Process mudev_cmd in server context. */
	err = muser_process_cmd(mudev, &mucmd);
	if (unlikely(err)) {
		muser_info("failed to mmap: %d", err);
		return err;
	}

	return vm_insert_pages(vma, mucmd.pg_map.pages, mucmd.pg_map.nr_pages);
}

struct mdev_parent_ops muser_mdev_fops = {
	.owner = THIS_MODULE,
	.supported_type_groups = mdev_type_groups,
	.create = muser_create,
	.remove = muser_remove,
	.open = muser_open,
	.release = muser_close,
	.read = muser_read,
	.write = muser_write,
	.ioctl = muser_ioctl,
	.mmap = muser_mmap,
};

/* copy vfio-client pages(mucmd.pg_map) to server(arg) */
static int bounce_out(void __user *arg, size_t argsz, struct mudev_cmd *mucmd)
{
	unsigned long to_copy, left;
	void __user *to;
	void *from;
	unsigned int offset;
	int i, ret = 0;

	left = mucmd->pg_map.len;
	if (argsz < left)
		return -EINVAL;

	offset = mucmd->pg_map.offset;

	for (i = 0; i < mucmd->pg_map.nr_pages && ret == 0; i++) {
		to_copy = min(left, PAGE_SIZE - offset);
		to = arg + (mucmd->pg_map.len - left);
		from = page_to_virt(mucmd->pg_map.pages[i]) + offset;

		ret = muser_copyout(to, from, to_copy);
		if (ret)
			return ret;

		left -= to_copy;

		/* Must be zero after first iteration. */
		offset = 0;
	}
	WARN_ON(left != 0);

	return 0;
}

/* copy from server(uaddr) to vfio-client pages(mucmd.pg_map) */
static int bounce_in(struct mudev_cmd *mucmd, void __user *uaddr)
{
	unsigned long to_copy, left;
	void __user *from;
	void *to;
	unsigned int offset;
	int i, ret;

	left = mucmd->pg_map.len;
	offset = mucmd->pg_map.offset;

	for (i = 0; i < mucmd->pg_map.nr_pages; i++) {
		to_copy = min(left, PAGE_SIZE - offset);
		from = uaddr + (mucmd->pg_map.len - left);
		to = page_to_virt(mucmd->pg_map.pages[i]) + offset;

		ret =  muser_copyin(to, from, to_copy);
		if (ret)
			return ret;

		left -= to_copy;

		/* Must be zero after first iteration. */
		offset = 0;
	}
	WARN_ON(left != 0);

	return 0;
}

static long install_fds(struct mudev_cmd *mucmd)
{
	int count = mucmd->muser_cmd.ioctl.data.irq_set.count;
	int i;
	long ret;

	mucmd->data_fds = kcalloc(count, sizeof(int32_t), GFP_KERNEL);
	if (mucmd->data_fds == NULL)
		return -ENOMEM;

	for (i = 0; i < count; i++) {
		if (mucmd->fds[i] == NULL) {
			mucmd->data_fds[i] = -1;
			continue;
		}
		mucmd->data_fds[i] = get_unused_fd_flags(0);
		if (mucmd->data_fds[i] < 0) {
			ret = mucmd->data_fds[i];
			muser_err("unable to get unused fd: %ld", ret);
			goto err;
		}
		fd_install(mucmd->data_fds[i], mucmd->fds[i]);
	}

	return 0;

err:
	for (i--; i >= 0; i--)
		put_unused_fd(mucmd->data_fds[i]);
	kfree(mucmd->data_fds);

	return ret;
}

static inline int maybe_install_fds(struct mudev_cmd *mucmd)
{
	unsigned int flags = mucmd->muser_cmd.ioctl.data.irq_set.flags;
	long ret = 0;

	if ((mucmd->muser_cmd.type == MUSER_IOCTL) &&
	    (mucmd->muser_cmd.ioctl.vfio_cmd == VFIO_DEVICE_SET_IRQS)) {
		switch ((flags & VFIO_IRQ_SET_DATA_TYPE_MASK)) {
		case VFIO_IRQ_SET_DATA_EVENTFD:
			ret = install_fds(mucmd);
			if (unlikely(ret))
				muser_dbg("failed to install fds: %ld", ret);
			break;
		/* TODO: SET_DATA_BOOL */
		}
	}

	return ret;
}

static inline int mmap_done(struct mudev_cmd * const mucmd)
{
	struct muser_cmd *cmd = &mucmd->muser_cmd;
	char __user *addr = (char __user *) cmd->mmap.response.addr;
	int ret;

	if (cmd->err < 0)
		return -1;
	ret = do_pin_pages(addr, mucmd->mmap_len, 1, &mucmd->pg_map);
	if (ret) {
		muser_alert("failed to pin pages: %d", ret);
		mucmd->pg_map.pages = NULL;
		mucmd->pg_map.nr_pages = 0;
	}
	return ret;
}

static long libmuser_unl_ioctl(struct file *filep,
				     unsigned int cmd, unsigned long arg)
{
	struct muser_dev *mudev = filep->private_data;
	struct mudev_cmd *mucmd;
	unsigned long offset;
	long ret = -EINVAL;

	WARN_ON(mudev == NULL);
	switch (cmd) {
	case MUSER_DEV_CMD_WAIT:
		/* Block until a request come from vfio. */
		ret = wait_event_interruptible(mudev->user_wait_q,
					       !list_empty(&mudev->cmd_list));
		if (unlikely(ret)) {
			muser_dbg("failed to wait for user space: %ld", ret);
			goto out;
		}

		/* Pick and remove the mucmd from the cmd_list. */
		mutex_lock(&mudev->dev_lock);
		WARN_ON(list_empty(&mudev->cmd_list));
		mucmd = list_first_entry(&mudev->cmd_list, struct mudev_cmd,
					 entry);
		list_del(&mucmd->entry);
		mutex_unlock(&mudev->dev_lock);

		/* Keep a reference to mudev_cmd in mudev. */
		WARN_ON(mudev->mucmd_pending != NULL);
		mudev->mucmd_pending = mucmd;
		/* TODO: These WARN_ON()s should really just detach mudev. */

		/* Populate userspace with mucmd. */
		ret = muser_copyout((void __user *)arg, &mucmd->muser_cmd,
				    sizeof(struct muser_cmd));
		if (ret)
			return -EFAULT;

		/* Install FDs on VFIO_SET_IRQS */
		ret = maybe_install_fds(mucmd);
		if (ret)
			return ret;

		break;
	case MUSER_DEV_CMD_DONE:
		/* This is only called when a command is pending. */
		if (mudev->mucmd_pending == NULL) {
			muser_dbg("done but no command pending");
			return -1;
		}

		/* Fetch (and clear) the pending command. */
		mucmd = mudev->mucmd_pending;
		mudev->mucmd_pending = NULL;

		/* Fetch response from userspace. */
		ret = muser_copyin(&mucmd->muser_cmd, (void __user *)arg,
				   sizeof(struct muser_cmd));
		if (ret)
			goto out;

		switch (mucmd->type) {
		case MUSER_IOCTL:
			offset = offsetof(struct muser_cmd, ioctl);
			offset += offsetof(struct muser_cmd_ioctl, data);
			ret = bounce_in(mucmd, (void __user *)(arg + offset));
			break;
		case MUSER_MMAP:
			ret = mmap_done(mucmd);
			break;
		case MUSER_WRITE:
		case MUSER_READ:
		case MUSER_DMA_MMAP:
		case MUSER_DMA_MUNMAP:
			break;
		default:
			muser_alert("bad command %d", mucmd->type);
			ret = -EINVAL;
			break;
		}

		/* Wake up vfio client. */
		up(&mudev->sem);
		break;

	default:
		muser_info("bad ioctl 0x%x", cmd);
		return -1;
	}

out:
	return ret;
}

#ifdef CONFIG_COMPAT
static long libmuser_compat_ioctl(struct file *filep,
					unsigned int cmd, unsigned long arg)
{
	arg = (unsigned long)compat_ptr(arg);
	return libmuser_unl_ioctl(filep, cmd, arg);
}
#endif				/* CONFIG_COMPAT */

static struct muser_dev *muser_get_dev_from_minor(int minor)
{
	struct muser_dev *mudev;

	/* Locate mudev using idr. */
	mutex_lock(&muser.muser_lock);
	mudev = idr_find(&muser.dev_idr, minor);
	mutex_unlock(&muser.muser_lock);

	return mudev;
}

static int libmuser_open(struct inode *inode, struct file *filep)
{
	struct muser_dev *mudev;
	int opened;

	/* Fetch corresponding mudev. */
	mudev = muser_get_dev_from_minor(iminor(inode));
	if (!mudev)
		return -ENOENT;

	/* Allow only one server for each mudev. */
	opened = atomic_cmpxchg(&mudev->srv_opened, 0, 1);
	if (opened)
		return -EBUSY;

	WARN_ON(filep->private_data != NULL);
	filep->private_data = mudev;

	return 0;
}

static int libmuser_release(struct inode *inode, struct file *filep)
{
	struct muser_dev *mudev = filep->private_data;
	int err;

	WARN_ON(mudev == NULL);
	mutex_lock(&mudev->dev_lock);
	/*
	 * FIXME must be per filep
	 */
	if (mudev->mucmd_pending) {
		muser_info("moving command back in list");
		list_add_tail(&mudev->mucmd_pending->entry, &mudev->cmd_list);
		mudev->mucmd_pending = NULL;
	}
	mutex_unlock(&mudev->dev_lock);

	err = dma_unmap_all(mudev, true);
	if (unlikely(err))
		muser_alert("failed to remove DMA maps");

	filep->private_data = NULL;
	atomic_dec(&mudev->srv_opened);

	return 0;
}

static inline int irq_set_data_eventfd(void __user * const buf,
		struct mudev_cmd * const mucmd)
{
	return muser_copyout((void __user *)buf, mucmd->data_fds,
		sizeof(__s32) * mucmd->muser_cmd.ioctl.data.irq_set.count);
}

static inline int irq_set_data_bool(void __user * const buf,
		struct mudev_cmd * const mucmd)
{
	return muser_copyout((void __user *)buf, mucmd->data_fds,
		sizeof(__u8) * mucmd->muser_cmd.ioctl.data.irq_set.count);
}

/*
 * Called by libmuser for kernel->user transfers.
 */
static ssize_t libmuser_read(struct file *filp, char __user *buf,
			     size_t bufsz, loff_t *ppos)
{
	struct muser_dev *mudev = filp->private_data;
	struct mudev_cmd *mucmd = mudev->mucmd_pending;
	int ret = -EINVAL;
	uint32_t irq_set_flags;

	if (!mucmd || !mudev) {
		muser_dbg("bad arguments");
		return -EINVAL;
	}

	if (!access_ok(buf, bufsz)) {
		muser_dbg("bad permissions");
		return -EFAULT;
	}

	switch (mucmd->type) {
	case MUSER_WRITE:
		ret = bounce_out(buf, bufsz, mucmd);
		if (ret) {
			muser_dbg("failed to copy to user: %d", ret);
			goto err;
		}
		break;
	case MUSER_IOCTL:
		/* FIXME move case into separate function */
		if (mucmd->muser_cmd.ioctl.vfio_cmd != VFIO_DEVICE_SET_IRQS) {
			muser_dbg("expected VFIO command %d, got %d instead",
				  VFIO_DEVICE_SET_IRQS,
				  mucmd->muser_cmd.ioctl.vfio_cmd);
			goto err;
		}
		irq_set_flags = mucmd->muser_cmd.ioctl.data.irq_set.flags &
			VFIO_IRQ_SET_DATA_TYPE_MASK;
		switch (irq_set_flags) {
		case VFIO_IRQ_SET_DATA_EVENTFD:
			ret = irq_set_data_eventfd((void __user *)buf, mucmd);
			if (unlikely(ret)) {
				muser_dbg("failed to set data eventfd: %d",
					  ret);
				goto err;
			}
			break;
		case VFIO_IRQ_SET_DATA_BOOL:
			ret = irq_set_data_bool((void __user *)buf, mucmd);
			if (unlikely(ret))
				goto err;
			break;
		default:
			muser_dbg("bad VFIO set IRQ flags %d", irq_set_flags);
			goto err;
		}
		break;
	default:
		muser_dbg("bad muser command %d", mucmd->type);
		goto err;
	}
	return bufsz;

err:
	return ret;
}

/*
 * Called by libmuser for user->kernel transfers.
 */
static ssize_t libmuser_write(struct file *filp, const char __user *buf,
			      size_t bufsz, loff_t *ppos)
{
	struct muser_dev *mudev = filp->private_data;
	struct mudev_cmd *mucmd = mudev->mucmd_pending;
	struct muser_cmd muser_cmd;
	int ret;

	if (!mucmd || !mudev) {
		muser_dbg("bad arguments");
		return -EINVAL;
	}

	if (!access_ok(buf, bufsz)) {
		muser_dbg("bad permissions");
		return -EFAULT;
	}

	ret = muser_copyin(&muser_cmd, (void __user *)buf,
			   sizeof(struct muser_cmd));
	if (ret)
		return ret;

	if (mucmd->type != muser_cmd.type) {
		muser_dbg("bad command %d", muser_cmd.type);
		return -EINVAL;
	}

	WARN_ON(muser_cmd.type != MUSER_READ);
	ret = bounce_in(mucmd, muser_cmd.rw.buf);
	if (ret)
		return ret;

	return bufsz;
}

static const struct file_operations libmuser_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = libmuser_unl_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = libmuser_compat_ioctl,
#endif
	.open = libmuser_open,
	.release = libmuser_release,
	.mmap = libmuser_mmap,
	.read = libmuser_read,
	.write = libmuser_write,
};

static void muser_device_release(struct device *dev)
{
	muser_info("muser dev released\n");
}

static char *muser_devnode(struct device *dev, umode_t *mode)
{
	return kasprintf(GFP_KERNEL, DRIVER_NAME "/%s", dev_name(dev));
}

static int __init muser_init(void)
{
	int ret;

	/* Initialise idr. */
	idr_init(&muser.dev_idr);
	mutex_init(&muser.muser_lock);
	INIT_LIST_HEAD(&muser.dev_list);

	/* Initialise class. */
	muser.class = class_create(THIS_MODULE, DRIVER_NAME);
	if (IS_ERR(muser.class))
		return PTR_ERR(muser.class);
	muser.class->devnode = muser_devnode;

	/* Allocate and register a chardev for muser devices. */
	ret = alloc_chrdev_region(&muser.muser_devt, 0, MINORMASK + 1,
				  DRIVER_NAME);
	if (ret)
		goto err_alloc_chrdev;

	cdev_init(&muser.muser_cdev, &libmuser_fops);
	ret = cdev_add(&muser.muser_cdev, muser.muser_devt, MINORMASK + 1);
	if (ret)
		goto err_cdev_add;

	muser.dev.class = muser.class;
	muser.dev.release = muser_device_release;
	dev_set_name(&muser.dev, "%s", DRIVER_NAME);

	ret = device_register(&muser.dev);
	if (ret)
		goto err_device_register;

	/* Register ourselves with mdev. */
	ret = mdev_register_device(&muser.dev, &muser_mdev_fops);
	if (ret)
		goto err_mdev_register_device;

	return 0;

err_mdev_register_device:
	device_unregister(&muser.dev);
err_device_register:
	cdev_del(&muser.muser_cdev);
err_cdev_add:
	unregister_chrdev_region(muser.muser_devt, MINORMASK + 1);
err_alloc_chrdev:
	class_destroy(muser.class);
	muser.class = NULL;
	return ret;
}

static void __exit muser_cleanup(void)
{
	struct muser_dev *mudev, *tmp;

	/* Remove all devices. */
	mutex_lock(&muser.muser_lock);
	list_for_each_entry_safe(mudev, tmp, &muser.dev_list, dlist_entry) {
		__muser_deinit_dev(mudev);
		kfree(mudev);
	}
	mutex_unlock(&muser.muser_lock);

	/* Unregister with mdev. */
	muser.dev.bus = NULL;
	mdev_unregister_device(&muser.dev);

	/* Cleanup everything else. */
	device_unregister(&muser.dev);
	idr_destroy(&muser.dev_idr);
	cdev_del(&muser.muser_cdev);
	unregister_chrdev_region(muser.muser_devt, MINORMASK + 1);
	class_destroy(muser.class);
	muser.class = NULL;
}

module_init(muser_init);
module_exit(muser_cleanup);

MODULE_LICENSE("Dual BSD/GPL");
