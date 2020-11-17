#include "bofdefs.h"
//Note if anyone else adopts or looks at this
//Its not threadsafe
typedef struct _item{
    void * elem;
    struct _item * next;
    struct _item * prev;
}item, *Pitem;

typedef struct _stack{\
    Pitem head;
    Pitem tail;
    void (*push)(struct _stack *, void *);
    void * (*pop)(struct _stack *);
    void (*free)(struct _stack *);
}stack, *Pstack;

void _push(Pstack q, void * v)
{
    Pitem i = (Pitem)intAlloc(sizeof(item));
    i->elem = v;
    if(q->head == NULL && q->tail == NULL) // empty
    {
        q->head = i;
        q->tail = i;
        i->next = NULL;
        i->prev = NULL;
    }else // not empty
    {
        q->tail->next = i;
        i->prev = q->tail;
        q->tail = i;
    }
}
void * _pop(Pstack q)
{
    void * retval = NULL;
    Pitem i = NULL;
    if(q->head == NULL && q->tail == NULL) // empty
    {
        return NULL;
    }
    retval = q->tail->elem;
    if(q->head == q->tail) //last elem
    {
        intFree(q->head);
        q->head = NULL;
        q->tail = NULL;
    }
    else // not the last item
    {
        i = q->tail;
        q->tail = i->prev;
        intFree(i);
    }
    return retval;
    
}

void _free(Pstack q)
{
    intFree(q);
}


Pstack stackInit()
{
    Pstack q = (Pstack)intAlloc(sizeof(stack));
    q->head = NULL;
    q->tail = NULL;
    q->push = _push;
    q->pop = _pop;
    q->free = _free;
    return q;
}