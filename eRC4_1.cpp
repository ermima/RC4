/*
RC4 encryption implementation
By Ermias Antigegn
*/

//Define the structure that holds the state of the RC4 algorithm
struct rc4_state
{
    int x; //Current index of the key scheduling
    int y; //Current imdex of Psedo-random generation
    int m[256];
//an array that holds the permutation of the key
};

//declare function that initialize the RC4 state with a key
void rc4_setup(struct rc4_state *s, unsigned char *key, int length);
//declare function that perform encryption and decryption
void rc4_crypt(struct rc4_state *s, unsigned char *data, int length);


#include <iostream>
#include <cstring>
#include <cstdlib>
//Include vector for dynamic array management
#include <vector>

using namespace std;

/* 
@ Let's define the function which initialaze the rc4 state.
@ It takes pointer to rc4_state structure, a pointer to a key, the length of the key
*/
void rc4_setup(struct rc4_state *s, unsigned char *key, int length)
{
    int i, j, k, *m, a;

 /*
        @ The state variables x and y are initialized to 0. 
        @The pointer m is assigned to point to the m array in the rc4_state structure.
    */
    s->x = 0;
    s->y = 0;
    m = s->m;
  


/*
      @ This loop initializes the state array m with values from 0 to 255. 
      @ Each index corresponds to its own value.
*/
    // Initialize state vector
    for (i = 0; i < 256; i++)
    {
        m[i] = i;
    }

/*
     @ j is index used in the key scheduling algorithm.
     @k is index for the key
*/
    j = k = 0;

    // Key scheduling
    /*
          @ For each imdex i it retrieves the value of m[i] to a,
          @ It updates the value of j using the current value of:
                            ==> j
                            ==>a
                            ==>the key at index k
           @ Swap tje value of the state array at j with at i  ==> m[i] with m[j]
           
    */
    for (i = 0; i < 256; i++)
    {
        a = m[i];
        j = (unsigned char)(j + a + key[k]);
        m[i] = m[j]; 
        m[j] = a;
        /*
              @ The key index k is incremented, and if it exceeds the key length, it wraps around to 0.
        */
        if (++k >= length) k = 0;

        /* Debug output for KSA
.e the current state of the m array */
        cout << "KSA Step " << i << ": m[" << i << "] = " << m[i] 
             << ", m[" << j << "] = " << m[j] << endl;
    }
}

void rc4_crypt(struct rc4_state *s, unsigned char *data, int length)
{
    int i, x, y, *m, a, b;

    x = s->x;
//Current index for the key scheduling.
    y = s->y;
//Current index for the pseudo-random generation.
    /*
           @The current values of x and y are retrieved from the rc4_state structure
    */
    m = s->m;
//Pointer to the state array m
    /*
          @ m is assigned to point to the state array.
    */

    // Encryption
    //This loop iterates over each byte of data to be encrypted or decrypted
    for (i = 0; i < length; i++)
    {
        x = (unsigned char)(x + 1); 
        a = m[x];
        y = (unsigned char)(y + a);
        m[x] = b = m[y];
        m[y] = a;
        data[i] ^= m[(unsigned char)(a + b)];
        
       /*
             @ The data byte at index i is XORed with the value from m[(a + b)], effectively encrypting or decrypting the byte
       */
        // Debug output for PRGA
        cout << "PRGA Step " << i << ": x = " << x 
             << ", y = " << y 
             << ", m[x] = " << (int)m[x] 
             << ", m[y] = " << (int)m[y] 
             << ", data[i] = " << (int)data[i] << endl;
    }

/*
      @ After processing all data, the updated values of x and y are stored back in the rc4_state structure
*/
    s->x = x;
    s->y = y;
}

int main()
{
/*
      @ We are going to declare two character arrays to hold the key and plaintext data. 
      @ The key can be up to 128 characters, and tphe plaintext can be up to 512 characters.
*/
    char key[128];
    char data[512];

    cout << "Enter key (max 128 characters): ";
    cin.getline(key, sizeof(key));

    cout << "Enter plaintext (max 512 characters): ";
    cin.getline(data, sizeof(data));

    struct rc4_state *s = new rc4_state(); // A pointer to rc4_state is created, and memory is allocated for it using new.

    cout << "Key : " << key << endl;
    cout << "Raw : " << data << endl;

    rc4_setup(s, (unsigned char *)key, strlen(key));
// The rc4_setup function is called to initialize the RC4 state with the provided key.

    // Store encrypted text in vector
    /* 
              @ Now we are going to declares a std::vector named encryptedData that will hold the encrypted text. 
              @ The size of the vector is initialized to the length of the plaintext (data). 
              @ Using unsigned char allows the vector to store binary data, which is suitable for encrypted output.
    */
    vector<unsigned char> encryptedData(strlen(data)); 
    /*
          @ This line uses the memcpy function to copy the contents of the data array (the plaintext) into the encryptedData vector. 
          @ The data() method of the vector returns a pointer to the underlying array, allowing memcpy to write directly to it. 
          @ The length of the data copied is determined by strlen(data), which gives the number of characters in the plaintext.
    */
    memcpy(encryptedData.data(), data, strlen(data)); // Copy plaintext to the vector

    rc4_crypt(s, encryptedData.data(), encryptedData.size());

    cout << "Encrypted (in unreadable format): ";
    for (size_t i = 0; i < encryptedData.size(); i++) {
        cout << encryptedData[i]; // Output raw binary data (may include non-printable characters)
    }

    cout << endl;

    // Reset the state for decryption
    rc4_setup(s, (unsigned char *)key, strlen(key));
    /*
           @ This line resets the RC4 state by calling the rc4_setup function again with the same key. 
           @ This is necessary because the state of the RC4 algorithm is modified during encryption, and it needs to be reset to decrypt the data correctly.
    */
    rc4_crypt(s, encryptedData.data(), encryptedData.size());
/*
        @ This line calls the rc4_crypt function again, this time to decrypt the previously encrypted data.
        @ It uses the same state s, the pointer to the encrypted data in the vector, and the size of the vector.
        @ After this call, the contents of encryptedData will be the original plaintext.
    */
    cout << "Decrypted : " << encryptedData.data() << endl;
    
   

    delete s; // Free the allocated memory
    return 0;
}
