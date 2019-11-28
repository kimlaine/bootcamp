// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "examples.h"
#include <vector>
#include <fstream>
#include <iostream>
#include <numeric>
#include <algorithm>

using namespace std;
using namespace seal;




void bootcamp_demo()
{
    // CLIENT'S VIEW

    // Vector of inputs
    size_t dimension = 1000;
    vector<double> inputs;
    inputs.reserve(dimension);
    for (size_t i = 0; i < dimension; i++) {
        inputs.push_back(i + 0.001 * i);
    };
    
    // Setting up encryption parameters
    EncryptionParameters parms(scheme_type::CKKS);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 50, 30, 50 }));

    // Set up the SEALContext
    auto context = SEALContext::Create(parms);

    cout << "Parameters are valid: " << boolalpha
        << context->key_context_data()->qualifiers().parameters_set << endl;
    cout << "Maximal allowed coeff_modulus bit-count for this poly_modulus_degree: "
        << CoeffModulus::MaxBitCount(poly_modulus_degree) << endl;
    cout << "Current coeff_modulus bit-count: "
        << context->key_context_data()->total_coeff_modulus_bit_count() << endl;
    
    // Use a scale of 2^30 to encode
    double scale = pow(2.0, 30);

    // Create a vector of plaintexts
    CKKSEncoder encoder(context);
    Plaintext pt;
    encoder.encode(inputs, scale, pt);

    // Set up keys
    KeyGenerator keygen(context);
    auto sk = keygen.secret_key();
    auto pk = keygen.public_key();

    // Set up Encryptor
    Encryptor encryptor(context, pk);

    // Create ciphertext
    Ciphertext ct;
    encryptor.encrypt(pt, ct);

    // Save to see size
    ofstream fs("test.ct", ios::binary);
    ct.save(fs);

    // Now send this vector to the server!
    // Also send the EncryptionParameters.
    // I'll show later how to do this.


    // SERVER'S VIEW

    // Load EncryptionParameters and set up SEALContext

    vector<double> weights;
    weights.reserve(dimension);
    for (size_t i = 0; i < dimension; i++) {
        weights.push_back((dimension & 1) ? -1.0 : 2.0);
    }

    Plaintext weight_pt;
    encoder.encode(weights, scale, weight_pt);

    // Create the Evaluator
    Evaluator evaluator(context);
    evaluator.multiply_plain_inplace(ct, weight_pt);

    
    // CLIENT'S VIEW ONCE AGAIN

    Decryptor decryptor(context, sk);

    // Decrypt the result
    Plaintext pt_result;
    decryptor.decrypt(ct, pt_result);

    // Decode the result
    vector<double> vec_result;
    encoder.decode(pt_result, vec_result);
    cout << "Result: " << accumulate(vec_result.cbegin(), vec_result.cend(), 0.0) << endl;
    cout << "True result: " << inner_product(inputs.cbegin(), inputs.cend(), weights.cbegin(), 0.0) << endl;
}




int main()
{
#ifdef SEAL_VERSION
    cout << "Microsoft SEAL version: " << SEAL_VERSION << endl;
#endif

    bootcamp_demo();

    while (false)
    {
        cout << "+---------------------------------------------------------+" << endl;
        cout << "| The following examples should be executed while reading |" << endl;
        cout << "| comments in associated files in native/examples/.       |" << endl;
        cout << "+---------------------------------------------------------+" << endl;
        cout << "| Examples                   | Source Files               |" << endl;
        cout << "+----------------------------+----------------------------+" << endl;
        cout << "| 1. BFV Basics              | 1_bfv_basics.cpp           |" << endl;
        cout << "| 2. Encoders                | 2_encoders.cpp             |" << endl;
        cout << "| 3. Levels                  | 3_levels.cpp               |" << endl;
        cout << "| 4. CKKS Basics             | 4_ckks_basics.cpp          |" << endl;
        cout << "| 5. Rotation                | 5_rotation.cpp             |" << endl;
        cout << "| 6. Performance Test        | 6_performance.cpp          |" << endl;
        cout << "+----------------------------+----------------------------+" << endl;

        /*
        Print how much memory we have allocated from the current memory pool.
        By default the memory pool will be a static global pool and the
        MemoryManager class can be used to change it. Most users should have
        little or no reason to touch the memory allocation system.
        */
        size_t megabytes = MemoryManager::GetPool().alloc_byte_count() >> 20;
        cout << "[" << setw(7) << right << megabytes << " MB] "
             << "Total allocation from the memory pool" << endl;

        int selection = 0;
        bool invalid = true;
        do
        {
            cout << endl << "> Run example (1 ~ 6) or exit (0): ";
            if (!(cin >> selection))
            {
                invalid = false;
            }
            else if (selection < 0 || selection > 6)
            {
                invalid = false;
            }
            else
            {
                invalid = true;
            }
            if (!invalid)
            {
                cout << "  [Beep~~] Invalid option: type 0 ~ 6" << endl;
                cin.clear();
                cin.ignore(numeric_limits<streamsize>::max(), '\n');
            }
        } while (!invalid);

        switch (selection)
        {
        case 1:
            example_bfv_basics();
            break;

        case 2:
            example_encoders();
            break;

        case 3:
            example_levels();
            break;

        case 4:
            example_ckks_basics();
            break;

        case 5:
            example_rotation();
            break;

        case 6:
            example_performance_test();
            break;

        case 0:
            return 0;
        }
    }

    return 0;
}