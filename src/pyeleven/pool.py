# -*- coding:utf-8 -*-
try:
    import Queue as Q
except ImportError:
    import queue as Q

from contextlib import contextmanager


class ObjectPool(object):
    """A simple thread safe object pool"""

    def __init__(self, create, destroy, bump, *args, **kwargs):
        super(ObjectPool, self).__init__()
        self.create = create
        self.destroy = destroy
        self.bump = bump
        self.args = args
        self.kwargs = kwargs
        self.maxSize = int(kwargs.get("maxSize", 1))
        self.queue = Q.PriorityQueue()

    def alloc(self):
        if self.queue.qsize() < self.maxSize and self.queue.empty():
            n = self.maxSize - self.queue.qsize()
            for i in range(0, n):  # try to allocate enough objects to fill to maxSize
                obj = self.create(*self.args, **self.kwargs)
                #print "allocated %s" % obj
                self.queue.put(obj)
        return self.queue.get()

    def free(self, obj):
        self.queue.put(obj)

    def invalidate(self, obj):
        self.destroy(obj, *self.args, **self.kwargs)


@contextmanager
def allocation(pool):
    obj = pool.alloc()
    try:
        yield obj
    except Exception, e:
        pool.invalidate(obj)
        obj = None
        raise e
    finally:
        if obj is not None:
            pool.bump(obj)
            pool.free(obj)
