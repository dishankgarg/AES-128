#include <bits/stdc++.h>
using namespace std;
#define ROTL8(x,shift) ((uint8_t) ((x) << (shift)) | ((x) >> (8 - (shift))))

class encryption{
    private:

        uint8_t S_BOX[16][16]; //S box for Substitution
        vector<vector<vector<uint8_t>>> Round_Keys;  //This will stores all Round Key Matrices for Decryption
        vector<vector<uint8_t>> State;  //Sore the Data of 16 Bytes / 128 bits
        vector<vector<uint8_t>> Round_key;  //Update in every Round
        vector<vector<uint8_t>> Key_Matrix;   //Cipher Key
        
        vector<uint8_t> Round_Constant {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36}; //Round Constant
        vector<vector<uint8_t>> K_Matrix =  {{0x02,0x03,0x01,0x01} , {0x01,0x02,0x03,0x01} , {0x01,0x01,0x02,0x03} , {0x03,0x01,0x01,0x02}}; //K matrix for Mix Column 
        
        //Generate the S box
        void GenerateSBox() {
            uint8_t p = 1, q = 1;
            do {
                p = p ^ (p << 1) ^ (p & 0x80 ? 0x1B : 0);
                q ^= q << 1;
                q ^= q << 2;
                q ^= q << 4;
                q ^= q & 0x80 ? 0x09 : 0;
                uint8_t xformed = q ^ ROTL8(q, 1) ^ ROTL8(q, 2) ^ ROTL8(q, 3) ^ ROTL8(q, 4);
                S_BOX[p >> 4][p & 0x0F] = xformed ^ 0x63;
            } while (p != 1);
            S_BOX[0][0] = 0x63;
            return;
        }
        
        //Generate Round Key
        // Rotating the last column of the key.
        // Applying the S-box transformation.
        // XORing with a round constant.
        // Generating subsequent round keys by XORing the results with previous round keys
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
        
        //Substituion of Bytes with help of S_BOX
        void E_Step_1(){
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
        
        //Shift Rows To left According to their Row number
        void E_Step_2(){
            for(int i=0;i<4;i++){
                rotate(this->State[i].begin(), this->State[i].begin() + i, this->State[i].end());
            }
            return;
        }
        
        //Mix Column (K Matrix with State Matrix)
        void E_Step_3(){
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
        
        //Add Round Key
        void E_Step_4(){
            for (int i = 0; i < 4; ++i) {
                for (int j = 0; j < 4; ++j) {
                    this->State[i][j] = this->State[i][j] ^ this->Round_key[i][j];
                }
            }
            return;
        }


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
        void Matrix_to_String(vector<vector<uint8_t>>& matrix) {
            string result;
            for (int col = 0; col < 4; ++col) {
                for (int row = 0; row < 4; ++row) {
                    uint8_t value = matrix[row][col];
                    result += static_cast<char>(value);
                }
            }
            cout<<"Encrypted Text : "<<result<<endl;
            return ;
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


        void XOR(vector<uint8_t> &a,vector<uint8_t> &b, vector<uint8_t> &result) {
            for (int i = 0; i < 4; ++i) {
                result[i] = a[i] ^ b[i];
            }
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

        friend class decryption;
    public:
        //Constructor to initialize all methods and data
        encryption(){
            GenerateSBox();

            string Key;
            string Plain_text;

            cout<<"Enter the Key : \n";          
            getline(cin, Key); 
            cout<<"Enter the Plain Text : \n";
            getline(cin, Plain_text);

            string_To_Input_Matrix(Key,this->Key_Matrix);
            string_To_Input_Matrix(Plain_text,this->State);

            this->Round_key = this->Key_Matrix;
            Round_Keys.push_back(Round_key);

            this->get_state();
            this->get_key();
            this->get_Round_Key(); 
            this->E_Process(); //process Initializes Here
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
        void E_Process(){
            //Round 0
            //Add Round Key(Initially the same as cipher Key) to the state matrix
            E_Step_4();
            cout<<"Round  :   0\n---------------------------------------------------- \nAdd Round Key\n";
            get_state();
            get_Round_Key();
            

            //Repeat all four steps for 9 times
            for(int i=1;i<=9;i++){
                cout<<"Round   :   "<<i<<endl;
                cout<<"----------------------------------------------------"<<endl;

                //Generates the Round Key 
                Generate_Round_Key(i-1);

                //Push it to the round keys vector for decryption purpose
                Round_Keys.push_back(Round_key);
                get_Round_Key();

                //Substituion Of Bytes
                E_Step_1();
                cout<<"Substitution of Bytes : \n";
                get_state();

                //Shift Rows to left according to their Row number
                E_Step_2();
                cout<<"Shift Row : \n";
                get_state();

                //Mix Column with K matrix
                E_Step_3();
                cout<<"Mix Column : \n";
                get_state();

                //Add the Round key to the State Matrix
                E_Step_4();
                cout<<"Add Roundkey : \n";
                get_state();
            }

            //In the 10th round, mix column will not perform

            cout<<"Round : 10"<<endl;
            cout<<"----------------------------------------------------"<<endl;
            cout<<"Round key : "<<endl;
                Generate_Round_Key(9);
                Round_Keys.push_back(Round_key);
                get_Round_Key();

                //Substitution of Bytes
                E_Step_1();
                cout<<"Substitution of Bytes : \n";
                get_state();

                //Shift Rows to left According to row number
                E_Step_2();
                cout<<"Shift Row : \n";
                get_state();

                //Add round Key
                E_Step_4();
                cout<<"Add Roundkey : \n";
                get_state();

                Matrix_to_String(State);
                return;

        }
};

class decryption{
    private:
    uint8_t Inv_S_BOX[16][16];
    vector<vector<uint8_t>> Inv_K_Matrix = {{0x0e,0x0b,0x0d,0x09}, {0x09,0x0e,0x0b,0x0d}, {0x0d,0x09,0x0e,0x0b}, {0x0b,0x0d,0x09,0x0e}};
    void generateInvSBox(const encryption& enc) {
            for (int i = 0; i < 16; ++i) {
                for (int j = 0; j < 16; ++j) {
                    uint8_t value = enc.S_BOX[i][j];
                    Inv_S_BOX[value >> 4][value & 0x0F] = (i << 4) | j;
                }
            }
            return;
        }
    
    //Rotate Row to right according to their row number
    void D_Step_1(encryption& enc){
                for(int i=0;i<4;i++){
                    rotate(enc.State[i].begin(), enc.State[i].begin() + 4 - i, enc.State[i].end());
                }
                return;
            }
    
    //Inverse Bytes Substitution with help of Inverse S_BOX
    void D_Step_2(encryption& enc){
                for (int i = 0; i < 4; ++i) {
                    for (int j = 0; j < 4; ++j) {
                        uint8_t value = enc.State[i][j];
                        uint8_t row = (value & 0xf0) >> 4;  
                        uint8_t col = value & 0x0f;        
                        enc.State[i][j] = Inv_S_BOX[row][col];
                    }
                }
                return;
            }
    
    //Add Round (this step is same on same but differece is only of the round key is different)
    void D_Step_3(encryption& enc,int a){
                for (int i = 0; i < 4; ++i) 
                    for (int j = 0; j < 4; ++j) 
                        enc.State[i][j] = enc.State[i][j] ^ enc.Round_Keys[a][i][j];
                return;
            }
    
    //Inverse Mix Column(Inverse K Matrix with State Matrix)
    void D_Step_4(encryption& enc){
            vector<vector<uint8_t>> result(4, vector<uint8_t>(4));
            for (int i = 0; i < 4; i++) {
                for (int j = 0; j < 4; j++) {
                    result[i][j] = enc.galois_multiply(this->Inv_K_Matrix[i][0], enc.State[0][j]) ^
                                enc.galois_multiply(this->Inv_K_Matrix[i][1], enc.State[1][j]) ^
                                enc.galois_multiply(this->Inv_K_Matrix[i][2], enc.State[2][j]) ^
                                enc.galois_multiply(this->Inv_K_Matrix[i][3], enc.State[3][j]);
                }
            }
            enc.State =  result;
        }

    public:
    decryption(encryption& enc){
        generateInvSBox(enc);
        //Add roundkey , Round 0
            //same round keys will be used but in reverse order 10 to 0
            D_Step_3(enc,10);
            cout<<"Round  :   0\n---------------------------------------------------- \nAdd Round Key\n";
            enc.get_state();
            enc.get_Round_Key(); 
            
            for(int i=9;i>=1;i--){
                cout<<"Round   :   "<<i<<endl;
                cout<<"----------------------------------------------------"<<endl;

                D_Step_1(enc);
                cout<<"Inverse Shift Row : \n";
                enc.get_state();

                D_Step_2(enc);
                cout<<"Inverse Substitution of Bytes : \n";
                enc.get_state();

                D_Step_3(enc,i);
                cout<<"Add Roundkey : \n";
                enc.get_state();

                D_Step_4(enc);
                cout<<"Inverse Mix Column : \n";
                enc.get_state();
            }
            cout<<"Round : 10"<<endl;
            cout<<"----------------------------------------------------"<<endl;
            cout<<"Round key : "<<endl;
            
                D_Step_1(enc);
                cout<<"Inverse Shift Row : \n";
                enc.get_state();

                D_Step_2(enc);
                cout<<"Inverse Substitution of Bytes : \n";
                enc.get_state();

                D_Step_3(enc,0);
                cout<<"Add Roundkey : \n";
                enc.get_state();

                enc.Matrix_to_String(enc.State);
                return;

    }
};
int main()
{
    encryption E1;
    decryption D1(E1);
    return 0;
}
