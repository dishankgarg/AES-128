#include <bits/stdc++.h>
using namespace std;
class encryption{
    private:
        vector<vector<uint8_t>> S_BOX = {
            {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76},
            {0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0},
            {0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15},
            {0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75},
            {0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84},
            {0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf},
            {0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8},
            {0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2},
            {0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},
            {0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb},
            {0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79},
            {0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08},
            {0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a},
            {0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e},
            {0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf} ,
            {0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16}}; 
        vector<vector<uint8_t>> K_Matrix =  {{0x02,0x03,0x01,0x01} , {0x01,0x02,0x03,0x01} , {0x01,0x01,0x02,0x03} , {0x03,0x01,0x01,0x02}}; 
        vector<uint8_t> Round_Constant {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36};
        vector<vector<uint8_t>> Key_Matrix;  
        vector<vector<uint8_t>> Round_key;
        vector<vector<uint8_t>> State;
        void string_To_Input_Matrix(string &input,vector<vector<uint8_t>> &temp) {
            temp = vector(4, vector<uint8_t>(4, 0x20));
            int length = input.size();
            for (int i = 0; i < length; ++i) {
                int row = i / 4;
                int col = i % 4;
                temp[col][row] = static_cast<uint8_t>(input[i]);
            }
            return;
        }
        void XOR(vector<uint8_t> &a,vector<uint8_t> &b, vector<uint8_t> &result) {
            for (int i = 0; i < 4; ++i) {
                result[i] = a[i] ^ b[i];
            }
        }
        void Generate_Round_Key(int i) {
            vector<uint8_t> temp(4);
            
            // Copy the initial key as w[0] to w[3]
            vector<vector<uint8_t>> w(4,vector<uint8_t>(4));
            for (int i = 0; i < 4; ++i) {
                for (int j = 0; j < 4; ++j) {
                    // Column-major to row-major
                    w[i][j] = Round_key[j][i];  
                }
            }

            //Step 1:Perform g(w[3])
            for (int i = 0; i < 4; ++i) {
                temp[i] = w[3][i];
            }

            // Rotate
            rotate(temp.begin(), temp.begin() + 1, temp.end());            
            

            // Substitute using S-box
            for (int i = 0; i < 4; ++i) {
                uint8_t value = temp[i];
                uint8_t row = (value & 0xf0) >> 4;  
                uint8_t col = value & 0x0f;        
                temp[i]= S_BOX[row][col];
            }
                 
            // Add round constant
            temp[0] ^=Round_Constant[i]; 

            // Step 2: Calculate w[4], w[5], w[6], w[7]
            XOR(w[0], temp, w[0]);  // w[4]
            XOR(w[0], w[1], w[1]);  // w[5]
            XOR(w[1], w[2], w[2]);  // w[6]
            XOR(w[2], w[3], w[3]);  // w[7]

            // Combine w[4] to w[7] back into the column-major format round key
            for (int i = 0; i < 4; ++i) {
                for (int j = 0; j < 4; ++j) {
                    Round_key[j][i] = w[i][j];
                }
            }
            return;
        }   
        void Matrix_to_String(vector<vector<uint8_t>>& matrix) {
            string result;
            for (int col = 0; col < 4; ++col) {
                for (int row = 0; row < 4; ++row) {
                    uint8_t value = matrix[col][row];
                    if(value!=0x20)
                    result += static_cast<char>(value);
                }
            }
            cout<<result;
            return ;
        }

    public:
        encryption(){
            string Key;
            string Plain_text;
            cout<<"Enter the Key : \n";          
            getline(cin, Key); 
            cout<<"Enter the Plain Text : \n";
            getline(cin, Plain_text);
            string_To_Input_Matrix(Key,this->Key_Matrix);
            string_To_Input_Matrix(Plain_text,this->State);
            this->Round_key = this->Key_Matrix;
        }
        uint8_t galois_multiply(uint8_t a, uint8_t b) {
            uint8_t p = 0;
            for (int i = 0; i < 8; i++) {
                if (b & 1) {
                    p ^= a;
                }
                bool carry = a & 0x80;
                a <<= 1;
                if (carry) {
                    a ^= 0x1B; // Irreducible polynomial x^8 + x^4 + x^3 + x + 1
                }
                b >>= 1;
            }
            return p;
        }      
        void get_key(){
            cout<<"Key\n------------\n";
            print_Matrix_Hex(Key_Matrix);
            cout<<endl;
        }
        void get_Round_Key(){
            cout<<"Round Key\n------------\n";
            print_Matrix_Hex(Round_key);
            cout<<endl;
        }
        void get_state(){
            cout<<"State Data\n------------\n";
            print_Matrix_Hex(State);
            cout<<endl;
        }
        void Step_1(){
        for (int i = 0; i < 4; ++i) {
            for (int j = 0; j < 4; ++j) {
                uint8_t value = this->State[i][j];
                uint8_t row = (value & 0xf0) >> 4;  
                uint8_t col = value & 0x0f;        
                this->State[i][j] = S_BOX[row][col];
            }
        }
        return;
    }
        void Step_2(){
            for(int i=0;i<4;i++){
                rotate(this->State[i].begin(), this->State[i].begin() + i, this->State[i].end());
            }
            return;
        }
        void Step_3(){
            vector<vector<uint8_t>> result(4, vector<uint8_t>(4));
            for (int i = 0; i < 4; i++) {
                for (int j = 0; j < 4; j++) {
                    result[i][j] = galois_multiply(this->K_Matrix[i][0], this->State[0][j]) ^
                                galois_multiply(this->K_Matrix[i][1], this->State[1][j]) ^
                                galois_multiply(this->K_Matrix[i][2], this->State[2][j]) ^
                                galois_multiply(this->K_Matrix[i][3], this->State[3][j]);
                }
            }
            this->State =  result;
        }
        void Step_4(){
            for (int i = 0; i < 4; ++i) {
                for (int j = 0; j < 4; ++j) {
                    this->State[i][j] = this->State[i][j] ^ this->Round_key[i][j];
                }
            }
            return;
        }
        void print_Matrix_Hex(const vector<vector<uint8_t>>& matrix) {
            int row = matrix.size();
            int col = matrix.size();
            for (int i=0;i<row;i++){
                for (int j=0;j<col;j++) {
                    // Print each byte as a two-digit hexadecimal number
                    cout << hex << setw(2) << setfill('0') << static_cast<int>(matrix[i][j]) << " ";
                }
                cout << endl;
            }
            return;
        }
        void Process(){
            //Add roundkey , Round 0
            Step_4();
            cout<<"Round  :   0\n---------------------------------------------------- \nAdd Round Key\n";
            get_state();
            get_Round_Key();
            
            for(int i=1;i<=9;i++){
                cout<<"Round   :   "<<i<<endl;
                cout<<"----------------------------------------------------"<<endl;
                Generate_Round_Key(i-1);
                get_Round_Key();

                Step_1();
                cout<<"Substitution of Bytes : \n";
                get_state();

                Step_2();
                cout<<"Shift Row : \n";
                get_state();

                Step_3();
                cout<<"Mix Column : \n";
                get_state();

                Step_4();
                cout<<"Add Roundkey : \n";
                get_state();
            }
            cout<<"Process Number : 10"<<endl;
            cout<<"----------------------------------------------------"<<endl;
            cout<<"Round key : "<<endl;
                Generate_Round_Key(9);
                get_Round_Key();
                Step_1();
                cout<<"Substitution of Bytes : \n";
                get_state();

                Step_2();
                cout<<"Shift Row : \n";
                get_state();

                Step_4();
                cout<<"Add Roundkey : \n";
                get_state();

                Matrix_to_String(State);
                return;

        }
};
int main()
{
    encryption E1;
    E1.get_state();
    E1.get_key();
    E1.get_Round_Key();
    E1.Process();
    return 0;
}