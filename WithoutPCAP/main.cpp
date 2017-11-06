#include <iostream>
#include <fstream>
#include <io.h>
#include <iomanip>
#include <QString>
#include <cstddef>
#include <QVector>
#include "packet.h"

using namespace std;
void showInBit(int num);
bool check (unsigned char* buf);
void protocol (int num);


ofstream output;
int main()
{
    system("CLS");
    unsigned char *buf=new unsigned char[4];
    unsigned char *temp_ch=new unsigned char;
    fstream file;
    QVector<packet> packets;
    //Пути к файлам поменять!!!
    output.open("D://Bunin/C++/MyCap/out.txt", ios::out );
    if (!output.is_open()) return -1;
    file.open("D://Bunin/C++/MyCap/my.pcap", ios::binary|ios::in);
    if (!file.is_open()) return -1;
    file.read((char*)buf, 3);
    int count=0;
    cout<<"Working..."<<endl;
    cout<<"Found packets: "<<count;

    while (file.gcount()>0)
    {
        bool ret=check(buf);
        if (ret==true)
        {
            packets.resize(count+1);
            cout<<"\r";
            cout<<"Found packets: "<<count+1;
            file.read((char*)temp_ch, 1);
            int temp=static_cast<int>(*temp_ch);
            packets[count].service.priority=temp>>5;
            packets[count].service.delay=temp&16;
            packets[count].service.throughput=temp&8;
            packets[count].service.reliability=temp&4;
            packets[count].service.ECN=temp&3;

            file.read((char*)buf, 2);
            int x=static_cast<int>(buf[0]);
            int y=static_cast<int>(buf[1]);
            x=x*256+y;
            packets[count].total_len=x;

            file.read((char*)buf, 2);
            x=static_cast<int>(buf[0]);
            y=static_cast<int>(buf[1]);
            temp=x*256+y;
            packets[count].identification=temp;

            file.read((char*)buf, 2);
            x=static_cast<int>(buf[0]);
            y=static_cast<int>(buf[1]);
            temp=x*256+y;
            packets[count].flag.reserved=temp&32768;
            packets[count].flag.fragment=temp&16384;
            packets[count].flag.more_fragments=temp&8192;
            packets[count].fragment_offset=temp&8191;

            file.read((char*)buf, 2);
            temp=static_cast<int>(buf[0]);
            packets[count].ttl=temp;
            temp=static_cast<int>(buf[1]);
            packets[count].protocol=temp;

            file.read((char*)buf, 2);
            x=static_cast<int>(buf[0]);
            y=static_cast<int>(buf[1]);
            temp=x*256+y;
            packets[count].checksum=temp;

            file.read((char*)buf, 4);
            temp=static_cast<int>(buf[0]);
            packets[count].sourse.x1=temp;
            temp=static_cast<int>(buf[1]);
            packets[count].sourse.x2=temp;
            temp=static_cast<int>(buf[2]);
            packets[count].sourse.x3=temp;
            temp=static_cast<int>(buf[3]);
            packets[count].sourse.x4=temp;

            file.read((char*)buf, 4);
            temp=static_cast<int>(buf[0]);
            packets[count].destination.x1=temp;
            temp=static_cast<int>(buf[1]);
            packets[count].destination.x2=temp;
            temp=static_cast<int>(buf[2]);
            packets[count].destination.x3=temp;
            temp=static_cast<int>(buf[3]);
            packets[count].destination.x4=temp;
            count++;
        }
        else
        {
            file.seekg(-2, ios::cur);
            file.read((char*)buf, 3);
        }
    }

    cout<<endl<<"Work is over"<<endl
       <<"You can find results in file out.txt";

    for (int i=0; i<packets.size(); i++)
    {
        output<<"Packet "<<i+1<<":\n"
             <<packets[i].out().toStdString().c_str()<<endl;
    }

    output.close();
    file.close();
    delete[] buf;
    delete temp_ch;
    return 0;
}

void showInBit(int num)
{
    QString byte;
    cout<<"function"<<endl;
    if (num>0)
        if(num<256)
            for (int i=7; i>=0; i--)
            {
                int temp=(num>>i)&1;
                byte.append(QString::number(temp));
                cout<<temp;
            }
        else
            if (num<65536)
                for (int i=15; i>=0; i--)
                {
                    int temp=(num>>i)&1;
                    byte.append(QString::number(temp));
                    cout<<temp;
                }
            else cout<<"Wrong number...";
    else
        cout<<"Wrong number...";

    cout<<endl<<"byte: "<<byte.toStdString()<<endl;
}

bool check (unsigned char *buf)
{
    int x=static_cast<int>(buf[2]);
    x=x>>4;
    QString temp;
    int arr[3];
    for (int i=0; i<3; i++)
        arr[i]=static_cast<int>(buf[i]);
    for (int i=0; i<2; i++)
    {
        if (arr[i]<10)
        {
            if (arr[i]==0)
                temp.append("00");
            else
            {
                temp.append('0');
                temp.append(QString::number(arr[i], 16));
            }
        }
        else
            temp.append(QString::number(arr[i], 16));
    }
    temp.append(QString::number(x, 16));
            if (temp=="08004")
//    if (temp=="32452")
    {
        return true;
    }
    else
    {
        return false;
    }
}
