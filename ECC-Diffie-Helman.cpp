/* 
	Author : Akhil Ravipati
	Description : A naive and basic implementation of ECC - Diffie Hellman secret key exchange
	Date: 27-07-2017
*/
#include<iostream>
#include "ECC.h"

using namespace std;

int main()
{
    ECC curve;

    int publicKeyAx, publicKeyAy, publicKeyBx, publicKeyBy, privateKeyA, privateKeyB;
    int secretAx, secretAy, secretBx, secretBy;

    privateKeyA = 121;
    curve.generateOwnPublicKey(privateKeyA, publicKeyAx, publicKeyAy);

    privateKeyB = 203;
    curve.generateOwnPublicKey(privateKeyB, publicKeyBx, publicKeyBy);

    cout<<"A's private key : "<<privateKeyA<<endl;
    cout<<"A's public key : ("<<publicKeyAx<<", "<<publicKeyAy<<") "<<endl;
    cout<<"-----------------\n\n";

    cout<<"B's private key : "<<privateKeyB<<endl;
    cout<<"B's public key : ("<<publicKeyBx<<", "<<publicKeyBy<<") "<<endl;
    cout<<"-----------------\n\n";

    curve.generateSecret(privateKeyA, publicKeyBx, publicKeyBy, secretAx, secretAy);
    curve.generateSecret(privateKeyB, publicKeyAx, publicKeyAy, secretBx, secretBy);

    cout<<"A's secret : ("<<secretAx<<", "<<secretAy<<") "<<endl;
    cout<<"B's secret : ("<<secretBx<<", "<<secretBy<<") "<<endl;

    return 0;
}
