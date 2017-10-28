/* 
	Author : Akhil Ravipati
	Description : A naive and basic implementation of ECC - Diffie Hellman secret key exchange
	Date: 27-07-2017
*/
#include<iostream>
using namespace std;

class ECC
{
    public:
    int p, a, b, gx, gy, n;

    ECC()
    {
        p = 211;
        a = 0;
        b = -4;

        gx = 2;
        gy = 2;
        n = 240;
    }

    int inverseModulo(int num)
    {
        //naive algorithm
        num = num%p;
        for(int x=1; x<p; x++)
            if((num*x)%p == 1)
                return x;
    }

    int negetiveModulo(int num)
    {
        while(num < 0)
            num += p;
        return num%p;
    }

    void addSame(int px, int py, int &rx, int &ry)
    {
        int lambda;
        int requiresNegetiveModulo = 0;
        int rnumerator = (3*px*px) + a;
        int rdenominator = 2*py;

        int numerator = abs(rnumerator);
        int denominator = abs(rdenominator);

        if(rnumerator*rdenominator < 0)
            requiresNegetiveModulo = 1;

        lambda = ((numerator%p) * inverseModulo(denominator))%p;
        if(requiresNegetiveModulo)
            lambda = ((negetiveModulo(-1)%p) * lambda)%p;

        rx = ((lambda*lambda) - px - px);
        ry = (lambda * (px-rx) - py);
        if(rx < 0)
            rx = negetiveModulo(rx);
        else
            rx = rx%p;

        if(ry < 0)
            ry = negetiveModulo(ry);
        else
            ry = ry%p;
    }

    void addDiff(int px, int py, int qx, int qy, int &rx, int &ry)
    {
        int lambda;
        int requiresNegetiveModulo = 0;
        int rnumerator = (qy - py);
        int rdenominator = (qx - px);

        int numerator = abs(rnumerator);
        int denominator = abs(rdenominator);

        if(rnumerator*rdenominator < 0)
            requiresNegetiveModulo = 1;

        lambda = ((numerator%p) * inverseModulo(denominator))%p;
        if(requiresNegetiveModulo)
            lambda = ((negetiveModulo(-1)%p) * lambda)%p;

        rx = ((lambda*lambda) - px - qx)%p;
        ry = (lambda * (px-rx) - py)%p;

        if(rx < 0)
            rx = negetiveModulo(rx);
        else
            rx = rx%p;

        if(ry < 0)
            ry = negetiveModulo(ry);
        else
            ry = ry%p;
    }

    int generateOwnPublicKey(int ownPrivateKey, int &rx, int &ry)
    {
        int tgx = gx, tgy = gy;

        if(ownPrivateKey == 1)
            return tgx;
        else
        {
            addSame(tgx, tgy, rx, ry);
            int counter = ownPrivateKey - 2;
            while(counter!=0)
            {
                addDiff(tgx, tgy, rx, ry, rx, ry);
                counter--;
            }
        }
    }

    int generateSecret(int ownPrivateKey, int othersPublicKeyx, int othersPublicKeyy, int &secretx, int &secrety)
    {
        if(ownPrivateKey == 1)
        {
            secretx = othersPublicKeyx;
            secrety = othersPublicKeyy;
        }
        else
        {
            addSame(othersPublicKeyx, othersPublicKeyy, secretx, secrety);
            int counter = ownPrivateKey - 2;
            while(counter!=0)
            {
                addDiff(othersPublicKeyx, othersPublicKeyy, secretx, secrety, secretx, secrety);
                counter--;
            }
        }
    }
};
