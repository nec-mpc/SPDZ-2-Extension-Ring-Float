#ifndef Z2N_SHARE_REPLICATED_H_
#define Z2N_SHARE_REPLICATED_H_

using namespace std;

#include <stdint.h>
#include <iostream>

template <typename T>
class Z2nShareReplicated {
 private:

 public:
  T elem1;
  T elem2;
  
  Z2nShareReplicated() {elem1=0; elem2=0;}

  Z2nShareReplicated& operator=(const Z2nShareReplicated& other)
  {
	  elem1 = other.elem1;
	  elem2 = other.elem2;
	  return *this;
  }

  bool operator !=(const Z2nShareReplicated& other) {
    if (elem1 != other.elem1 || elem2 != other.elem2) return false;
    return true;
  }

  Z2nShareReplicated operator+(const Z2nShareReplicated& other) {
    Z2nShareReplicated tmp;
    tmp.elem1 = elem1 + other.elem1;
    tmp.elem2 = elem2 + other.elem2;
    return tmp;
  }


  Z2nShareReplicated operator-(const Z2nShareReplicated& other) {
    Z2nShareReplicated tmp;
      tmp.elem1 = elem1 - other.elem1;
      tmp.elem2 = elem2 - other.elem2;
    return tmp;
  }

  
  Z2nShareReplicated operator*(const Z2nShareReplicated& other) {
    Z2nShareReplicated tmp;
    tmp.elem1 = elem1 * other.elem1;
    tmp.elem2 = elem2 * other.elem2;
    return tmp;
  }

  Z2nShareReplicated& operator+=(const Z2nShareReplicated& other) {
    elem1 = elem1 + other.elem1;
    elem2 = elem2 + other.elem2;
    return *this;
  }

  Z2nShareReplicated& operator-=(const Z2nShareReplicated& other) {
	  elem1 = elem1 - other.elem1;
	  elem2 = elem2 - other.elem2;
	  return *this;
  }

  Z2nShareReplicated& operator*=(const Z2nShareReplicated& other) {
	  elem1 = elem1 * other.elem1;
	  elem2 = elem2 * other.elem2;
	  return *this;
  }

  void dump() {
      cout <<  elem1<< ", " << elem2 << endl;
  }

};

#endif //Z2N_SHARE_REPLICATED_H_
