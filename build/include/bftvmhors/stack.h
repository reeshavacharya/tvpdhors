#ifndef BFTVMHORS_STACK_H
#define BFTVMHORS_STACK_H

#include <bftvmhors/types.h>


#define STACK_PUSH_SUCCESS 0
#define STACK_PUSH_FAILED 1

#define STACK_POP_FAILED NULL
#define STACK_TOP_FAILED NULL


/// Implements the stack structure for elements of type void *
typedef struct stack{
    void ** data;
    u32 capacity;
    u32 length;
}stack_t;


/// Initializes a new stack with the given size
/// \param stack Pointer to the stack
/// \param size Capacity of the stack
void stack_init(stack_t * stack, u32 size);


/// Push a void * element to the stack
/// \param stack Pointer to the stack struct
/// \param element Void * element
/// \return Returns STACK_PUSH_SUCCESS, STACK_PUSH_FAILED
u32 stack_push(stack_t * stack, void * element);

/// Pops an element from the stack
/// \param stack Pointer to the stack struct
/// \return Void * or NULL if stack is empty
void * stack_pop(stack_t * stack);


/// Returns the top of the stack
/// \param stack Pointer to the stack
/// \return Void * or NULL if stack is empty
void * stack_top(stack_t * stack);


/// Gets the size of the stack
/// \param stack Pointer to the stack
/// \return Length of the stack
u32 stack_getsize(stack_t * stack);



#endif