#include "bofdefs.h"
//Not if anyone else adopts or looks at this
//Its not threadsafe
typedef struct _item{
    void * elem;
    struct _item * next;
}item, *Pitem;

typedef struct _queue{\
    Pitem head;
    Pitem tail;
    void (*push)(struct _queue *, void *);
    void * (*pop)(struct _queue *);
    void (*free)(struct _queue *);
}queue, *Pqueue;

void _push(Pqueue q, void * v)
{
    Pitem i = (Pitem)intAlloc(sizeof(item));
    i->elem = v;
    if(q->head == NULL && q->tail == NULL) // empty
    {
        q->head = i;
        q->tail = i;
        i->next = NULL;
    }else // not empty
    {
        q->tail->next = i;
        q->tail = i;
    }
}
void * _pop(Pqueue q)
{
    void * retval = NULL;
    Pitem i = NULL;
    if(q->head == NULL && q->tail == NULL) // empty
    {
        return NULL;
    }
    retval = q->head->elem; //scanbuild false positive
    if(q->head == q->tail) //last elem
    {
        intFree(q->head);
        q->head = NULL;
        q->tail = NULL;
    }
    else // not the last item
    {
        i = q->head;
        q->head = q->head->next;
        intFree(i);
    }
    return retval;
    
}

void _free(Pqueue q)
{
    intFree(q);
}

Pqueue queueInit()
{
    Pqueue q = (Pqueue)intAlloc(sizeof(queue));
    q->head = NULL;
    q->tail = NULL;
    q->push = _push;
    q->pop = _pop;
    q->free = _free;
    return q;
}