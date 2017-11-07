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
void sort_bubble(QVector<packet> &vec, int num);
void sort_hoar(QVector<packet> &vec, int left, int right);
void sort_merge(QVector<packet> &vec, int left, int right, int num);
bool comp(packet a, packet b);


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

    cout<<endl<<"Reading is over"<<endl
       <<"You can find results in file out.txt"<<endl<<"Now sorting...";
    QVector<packet> packets_temp;
    for (int i=0; i<packets.size(); i++)
    {
        output<<"Packet "<<i+1<<": "<<packets[i].destination_string().toStdString()<<"\n"
             <<packets[i].out().toStdString().c_str()<<endl;
    }

    packets_temp=packets;
    fstream file_bubble;
    file_bubble.open("D://Bunin/C++/MyCap/bubble.txt", ios::out );
    if (!file_bubble.is_open()) return -1;
    sort_bubble(packets_temp,packets_temp.size());
    for (int i=0; i<packets_temp.size(); i++)
    {
        file_bubble<<"Packet "<<i+1<<": "<<packets_temp[i].destination_string().toStdString()<<"\n"
                  <<packets_temp[i].out().toStdString().c_str()<<endl;
    }

    packets_temp=packets;
    fstream file_hoar;
    file_hoar.open("D://Bunin/C++/MyCap/hoar.txt", ios::out );
    if (!file_hoar.is_open()) return -1;
    sort_hoar(packets_temp, 0, packets_temp.size()-1);
    for (int i=0; i<packets_temp.size(); i++)
    {
        file_hoar<<"Packet "<<i+1<<": "<<packets_temp[i].destination_string().toStdString()<<"\n"
                  <<packets_temp[i].out().toStdString().c_str()<<endl;
    }

    packets_temp=packets;
    fstream file_merge;
    file_merge.open("D://Bunin/C++/MyCap/merge.txt", ios::out );
    if (!file_merge.is_open()) return -1;
    sort_merge(packets_temp, 0, packets_temp.size()-1, packets_temp.size());
    for (int i=0; i<packets_temp.size(); i++)
    {
        file_merge<<"Packet "<<i+1<<": "<<packets_temp[i].destination_string().toStdString()<<"\n"
                 <<packets_temp[i].out().toStdString().c_str()<<endl;
    }

    cout<<endl<<"Done";
    file_merge.close();
    file_bubble.close();
    file_hoar.close();
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
    {
        return true;
    }
    else
    {
        return false;
    }
}
bool less_ip(ip_address a, ip_address b)
{
    if (a.x1<b.x1)  return true;
    else
        if (a.x1==b.x1)
            if (a.x2<b.x2)   return true;
            else
                if (a.x2==b.x2)
                    if (a.x3<b.x3) return true;
                    else
                        if (a.x3==b.x3)
                            if (a.x4<b.x4)  return true;
                            else return false;
                        else return false;
                else return false;
        else return false;

}
bool comp(packet a, packet b)
{
    if (a.destination.x1<b.destination.x1)  return true;
    else
        if (a.destination.x1==b.destination.x1)
            if (a.destination.x2<b.destination.x2)   return true;
            else
                if (a.destination.x2==b.destination.x2)
                    if (a.destination.x3<b.destination.x3) return true;
                    else
                        if (a.destination.x3==b.destination.x3)
                            if (a.destination.x4<b.destination.x4)  return true;
                            else return false;
                        else return false;
                else return false;
        else return false;

}
void sort_bubble(QVector<packet> &vec, int num)
{
    for (int i=0; i<num-1; i++)
        for (int j=0; j<num-i-1; j++)
            if (comp(vec[j+1], vec[j])==true)
                swap(vec[j], vec[j+1]);
}
void sort_hoar(QVector<packet> &vec, int left, int right)
{
    int i=left;
    int j=right;
    int mid=(left+right+1)/2;
    do
    {
        while (comp(vec[i], vec[mid])==true)
            i++;
        while (comp(vec[mid], vec[j])==true)
            j--;
        if (i<=j)
        {
            if (i<j) swap(vec[i], vec[j]);
            i++;
            j--;
        }
    } while (i<=j);
    if (i<right) sort_hoar(vec, i, right);
    if (j>left) sort_hoar(vec, left, j);
}
void sort_merge (QVector<packet> &vec, int left, int right, int num)
{
    if (left==right) return;
    if (right-left==1)
    {
        if (comp(vec[right], vec[left])==true)
            swap (vec[left], vec[right]);
        return;
    }
    int mid = (left+right)/2;
    sort_merge(vec, left, mid, num);
    sort_merge(vec, mid+1, right, num);

    QVector<packet> vec_temp;
    vec_temp=vec;
    int _left=left;
    int _right=mid+1;
    int cur=0;

    while (right-left+1 != cur)
    {
        if (_left>mid)
        {
            vec_temp[cur]=vec[_right];
            cur++; _right++;
        }
        else if (_right>right)
        {
            vec_temp[cur]=vec[_left];
            cur++; _left++;
        }
        else if (comp(vec[_right], vec[_left]))
        {
            vec_temp[cur]=vec[_right];
            cur++; _right++;
        }
        else
        {
            vec_temp[cur]=vec[_left];
            cur++; _left++;
        }
    }
    for (int i=0; i<cur; i++)
        vec[i+left]=vec_temp[i];
}
















