// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "examples.h"
#include <vector>
#include <fstream>
#include <iostream>
#include <numeric>

using namespace std;
using namespace seal;




void bootcamp_demo()
{
    // CLIENT'S VIEW

    // Vector of inputs
    vector<int64_t> inputs{ 3, 4, 5, 6, 7, 8 };
    
    // Setting up encryption parameters
    EncryptionParameters parms(scheme_type::BFV);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));

    // All computations happen modulo 2^20!
    parms.set_plain_modulus(1ULL << 20);

    // Set up the SEALContext
    auto context = SEALContext::Create(parms);

    // Create a vector of plaintexts
    vector<Plaintext> pts;
    IntegerEncoder int_encoder(context);
    for (auto val : inputs) {
        pts.emplace_back(int_encoder.encode(val));
    }

    // Set up keys
    KeyGenerator keygen(context);
    auto sk = keygen.secret_key();
    auto pk = keygen.public_key();

    // Set up Encryptor
    Encryptor encryptor(context, pk);

    // Create a vector of ciphertexts
    vector<Ciphertext> cts;
    for (const auto& p : pts) {
        Ciphertext new_ct;
        encryptor.encrypt(p, new_ct);
        cts.emplace_back(move(new_ct));
    }

    // Now send this vector to the server!
    // Also send the EncryptionParameters.
    // I'll show later how to do this.


    // SERVER'S VIEW

    // Load EncryptionParameters and set up SEALContext

    vector<int64_t> weights{ 1, 2, -1, -2, 1, 2 };
    vector<Plaintext> weight_pts;
    for (auto w : weights) {
        weight_pts.emplace_back(int_encoder.encode(w));
    }

    // Create the Evaluator
    Evaluator evaluator(context);
    for (auto i = 0; i < cts.size(); i++) {
        evaluator.multiply_plain_inplace(cts[i], weight_pts[i]);
    }

    // Sum up the ciphertexts
    Ciphertext ct_result;
    evaluator.add_many(cts, ct_result);

    
    // CLIENT'S VIEW ONCE AGAIN

    Decryptor decryptor(context, sk);

    // Decrypt the result
    Plaintext pt_result;
    decryptor.decrypt(ct_result, pt_result);

    // Decode the result
    cout << "Result: " << int_encoder.decode_int64(pt_result) << endl;
    cout << "True result: " << inner_product(inputs.cbegin(), inputs.cend(), weights.cbegin(), 0) << endl;
}




int main()
{
    bootcamp_demo();

#ifdef SEAL_VERSION
    cout << "Microsoft SEAL version: " << SEAL_VERSION << endl;
#endif
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