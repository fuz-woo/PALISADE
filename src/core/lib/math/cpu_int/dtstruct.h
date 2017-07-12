/**
 * @file dtstruct.h This code provides basic queueing functionality.
 * @author  TPOC: palisade@njit.edu
 *
 * @copyright Copyright (c) 2017, New Jersey Institute of Technology (NJIT)
 * All rights reserved.
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice, this
 * list of conditions and the following disclaimer in the documentation and/or other
 * materials provided with the distribution.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */
/*
 *	This code provides basic queueing functionality.
 */

#ifndef LBCRYPTO_MATH_CPU_INT_DTSTRUCT_H
#define LBCRYPTO_MATH_CPU_INT_DTSTRUCT_H

#include <iostream>
#include <stdexcept>
#include "../../utils/inttypes.h"
#include <queue>

/**
 * @namespace cpu8bit
 * The namespace of cpu8bit
 */
namespace cpu_int {

//const usint FRAGMENTATION_FACTOR = 14;	//!< @brief ???
// const usint FRAGMENTATION_FACTOR = 27;

const usint BUFFER_SIZE = 1024 * 512;// *FRAGMENTATION_FACTOR; //!< @brief Amount of memory stored in the queue data structure.

/**
 * @brief circular character array implementation of queue used for memory pools
 */
template<typename uint_t, usint BITLENGTH>
class CircularQueue
{
private:
	int m_front, m_back, m_size, m_count;
	/*uschar* m_array[BUFFER_SIZE/FRAGMENTATION_FACTOR];*/
	uint_t* m_array[BUFFER_SIZE];
public:
	/**
	 * Basic constructor.	  	  
	 */
	CircularQueue();

	/**
	 * Push operator to push data onto the queue.	
	 *  	  
	 * @param item the data to push onto the queue.
	 */
	void Push(uschar* item);

	/**
	 * Show the data in the queue by printing to stdout.  Prints a message if the queue is empty.
	 */
	void Show();

	/**
	 * Pop data from the queue.
	 */
	void Pop();

	/**
	 * Returns the size of the queue.
	 *  	  
	 * @return the size of the queue.
	 */
	int GetSize();
	//int GetFront();

	/**
	 * Returns the position of the back of the queue.
	 *  	  
	 * @return the back of the queue.
	 */
	int GetBack();

	/**
	 * Returns the data at the front of the queue.
	 *  	  
	 * @return the data at the front of the queue.
	 */
	uschar* GetFront();
};

}

#endif