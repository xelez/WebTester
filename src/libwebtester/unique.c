/*
 * ================================================================================
 *  unique.h - part of the WebTester Server
 * ================================================================================
 *
 *  Written (by Nazgul) under General Public License.
 *
*/

#include "unique.h"

#include <malloc.h>
#include <memory.h>

void
unique_done                        (void)
{
}

unique_pool_t*
unique_pool_create                 (void)
{
  long i;
  unique_pool_t *ptr;
  ptr=malloc (sizeof (unique_pool_t));

  for (i=0; i<MAX_UNIQUE; i++)
    ptr->stack[i]=i;

  ptr->ptr=0;

  return ptr;
}

void
unique_pool_destroy                (unique_pool_t *__self)
{
  if (!__self) return;
  free (__self);
}

int
unique_alloc_uid                   (unique_pool_t *__self)
{
  if (!__self || __self->ptr>=MAX_UNIQUE) return -1;
  return __self->stack[__self->ptr++];
}

void
unique_release_uid                 (unique_pool_t *__self, unsigned short __uid)
{
  if (!__self || __self->ptr<=0) return;
  __self->stack[--__self->ptr]=__uid;
}

BOOL
unique_pool_empty                  (unique_pool_t *__self)
{
  if (!__self) return -1;
  return __self->ptr>=MAX_UNIQUE;
}

BOOL
unique_pool_full                   (unique_pool_t *__self)
{
  if (!__self) return -1;
  return __self->ptr==0;
}
