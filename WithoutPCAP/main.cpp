#include <iostream>
#include <fstream>
#include <io.h>
#include <iomanip>
#include <QString>
#include <cstddef>
#include <QVector>
#include <QTime>
#include "packet.h"

using namespace std;
void showInBit(int num);
bool check (unsigned char* buf);
void protocol (int num);
void sort_bubble(QVector<packet> &vec, int num);
void sort_hoar(QVector<packet> &vec, int left, int right);
void sort_merge(QVector<packet> &vec, int left, int right, int num);
bool comp(packet a, packet b);
int search_simple(QVector<packet> vec, ip_address temp);
int search_binary (QVector<packet> vec, int left, int right, ip_address key);

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
    if (!file.is_open())
    {
        cout<<"File *.pcap not found!";
        return -1;
    }
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
    QTime timer_bubble;
    timer_bubble.start();
    sort_bubble(packets_temp,packets_temp.size());
    int time_bubble=timer_bubble.elapsed();
    cout<<endl<<endl<<"Sorting time:"<<endl<<"  Bubble:\t"<<time_bubble<<endl;
    for (int i=0; i<packets_temp.size(); i++)
    {
        file_bubble<<"Packet "<<i+1<<": "<<packets_temp[i].destination_string().toStdString()<<"\n"
                  <<packets_temp[i].out().toStdString().c_str()<<endl;
    }

    packets_temp=packets;
    fstream file_hoar;
    file_hoar.open("D://Bunin/C++/MyCap/hoar.txt", ios::out );
    if (!file_hoar.is_open()) return -1;
    QTime timer_hoar;
    timer_hoar.start();
    sort_hoar(packets_temp, 0, packets_temp.size()-1);
    int time_hoar=timer_hoar.elapsed();
    cout<<"  Hoar:\t\t"<<time_hoar;
    for (int i=0; i<packets_temp.size(); i++)
    {
        file_hoar<<"Packet "<<i+1<<": "<<packets_temp[i].destination_string().toStdString()<<"\n"
                <<packets_temp[i].out().toStdString().c_str()<<endl;
    }

    packets_temp=packets;
    fstream file_merge;
    file_merge.open("D://Bunin/C++/MyCap/merge.txt", ios::out );
    if (!file_merge.is_open()) return -1;
    QTime timer_merge;
    timer_merge.start();
    sort_merge(packets_temp, 0, packets_temp.size()-1, packets_temp.size());
    int time_merge=timer_merge.elapsed();
    cout<<endl<<"  Merge:\t"<<time_merge;
    for (int i=0; i<packets_temp.size(); i++)
    {
        file_merge<<"Packet "<<i+1<<": "<<packets_temp[i].destination_string().toStdString()<<"\n"
                 <<packets_temp[i].out().toStdString().c_str()<<endl;
    }

    packets_temp=packets;
    fstream file_sort;
    file_sort.open("D://Bunin/C++/MyCap/sort.txt", ios::out );
    if (!file_sort.is_open()) return -1;
    QTime timer_sort;
    timer_sort.start();
    sort(packets_temp.begin(), packets_temp.end());
    int time_sort=timer_sort.elapsed();
    cout<<endl<<"  STL:\t\t"<<time_sort<<endl;
    for (int i=0; i<packets_temp.size(); i++)
    {
        file_sort<<"Packet "<<i+1<<": "<<packets_temp[i].destination_string().toStdString()<<"\n"
                <<packets_temp[i].out().toStdString().c_str()<<endl;
    }

    cout<<endl<<"Finding ip: 192.168.43.109 ..."<<endl;
    ip_address temp;
    temp.x1=213;
    temp.x2=180;
    temp.x3=204;
    temp.x4=90;
    QTime timer_simple;
    timer_simple.start();
    int number=search_simple(packets, temp);
    int time_simple=timer_simple.elapsed();
    cout<<"Searching time:"<<endl
       <<"  Simple:\t\t"<<time_simple<<endl;
    QTime timer_binary;
    timer_binary.start();
    int number_bin=search_binary(packets_temp, 0, packets_temp.size(), temp);
    int time_binary=timer_binary.elapsed();
    cout<<"  Binary:\t\t"<<time_binary<<endl;
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
//bool comp(packet a, packet b)
//{
//    if (a.destination.x1<b.destination.x1)  return true;
//    else
//        if (a.destination.x1==b.destination.x1)
//            if (a.destination.x2<b.destination.x2)   return true;
//            else
//                if (a.destination.x2==b.destination.x2)
//                    if (a.destination.x3<b.destination.x3) return true;
//                    else
//                        if (a.destination.x3==b.destination.x3)
//                            if (a.destination.x4<b.destination.x4)  return true;
//                            else return false;
//                        else return false;
//                else return false;
//        else return false;

//}
void sort_bubble(QVector<packet> &vec, int num)
{
    for (int i=0; i<num-1; i++)
        for (int j=0; j<num-i-1; j++)
            if (vec[j+1]<vec[j])
                swap(vec[j], vec[j+1]);
}
void sort_hoar(QVector<packet> &vec, int left, int right)
{
    int i=left;
    int j=right;
    int mid=(left+right+1)/2;
    do
    {
        while (vec[i]<vec[mid])
            i++;
        while (vec[mid]<vec[j])
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
        if (vec[right]<vec[left])
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
        else if (vec[_right]<vec[_left])
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

int search_simple(QVector<packet> vec, ip_address temp)
{
    for (int i=0; i<vec.size(); i++)
        if (vec[i].destination==temp)
            return i;
    return -1;
}
int search_binary (QVector<packet> vec, int left, int right, ip_address key)
{
    int midd = 0;
    while (1)
    {
        midd = (left + right) / 2;

        if (key < vec[midd].destination)       // если искомое меньше значения в ячейке
            right = midd - 1;      // смещаем правую границу поиска
        else if (vec[midd].destination < key )  // если искомое больше значения в ячейке
            left = midd + 1;	   // смещаем левую границу поиска
        else                       // иначе (значения равны)
            return midd;           // функция возвращает индекс ячейки

        if (left > right)          // если границы сомкнулись
            return -1;
    }
}













