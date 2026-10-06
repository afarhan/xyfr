#include <Arduino.h>
#include "queue.h"
// non-blocking, in-memory queuing system for sound sample pipes */

/** queue functions 

we use these queues for piping pcm samples.

There are a couple of interesting, non-standard behaviours in this queue.
First, these never block. second, dequeing from an empty queue will
return '0'samples.

*/

void q_init(struct Queue *p){
	p->head = 0;
	p->tail = 0;
	p->count = 0;
	p->stall = 1;
}

void q_reset(struct Queue *p){
	p->stall = 1;   // set first: a concurrent q_read reads silence during the reset
	p->count = 0;
	p->head  = 0;
	p->tail  = 0;
}

void q_write(struct Queue *p, int16_t w){
	if (p->count == MAX_Q)
		return;

	p->data[p->head++] = w;
	p->count++;
	if (p->head == MAX_Q)
		p->head = 0;
	if (p->count > 1600 && p->stall == 1)
		p->stall = 0;
}

int16_t q_read(struct Queue *p){
	int16_t data;

	if (!p->count || p->stall)
		return 0;

	data = p->data[p->tail++];
	p->count--;
	if (p->tail == MAX_Q)
		p->tail = 0;
	return data;
}
