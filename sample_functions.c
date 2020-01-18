#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <math.h>


void swap(int *xp, int *yp) 
{ 
    int temp = *xp; 
    *xp = *yp; 
    *yp = temp; 
} 

void bubbleSort3(int arr[], int n) 
{ 
   int i, j; 
	n = 3;
   for (i = 0; i < n-1; i++)       
  
       // Last i elements are already in place    
       for (j = 0; j < n-i-1; j++)  
           if (arr[j] > arr[j+1]) 
              swap(&arr[j], &arr[j+1]); 
} 

int isSorted3(int arr[], int n)
{
	int i;
	n=3;
	for (i = 0; i < n - 1; i++)
		if (arr[i] > arr[i+1])
			return 0;
	return 1;
}

int getMax3(int arr[], int n)
{
	int i;
	n=3;
	int max = 0;
	for (i = 0; i < n; i++)
		if (arr[i] > max)
			max = arr[i];
	return max;
}

float getAverage3(float arr[], int n)
{
	n=3;
	float sum = 0.0;
	int i;
	for (i = 0; i < n; i++)
		sum += arr[i];
	return sum / n;
}

float square(float x )
{
    float p;
    p = x * x;
    return p;
}

int checkPrimeNumber(int n) {
    int i, flag = 1;
    for (i = 2; i <= n / 2; ++i) {
        if (n % i == 0) {
            flag = 0;
            break;
        }
    }
    return flag;
}

int binToDec(long long n) {
    int dec = 0, i = 0, rem;
    while (n != 0) {
        rem = n % 10;
        n /= 10;
        dec += rem * pow(2, i);
        ++i;
    }
    return dec;
}

long long decToBin(int n) {
    long long bin = 0;
    int rem, i = 1, step = 1;
    while (n != 0) {
        rem = n % 2;
        n /= 2;
        bin += rem * i;
        i *= 10;
    }
    return bin;
}

int getNumDigits(int num) {
    int count = 0;
    while (num != 0) {
        num /= 10;
        ++count;
    }
    return count;
}

int main(int argc, char **argv)
{
	return 0;
}