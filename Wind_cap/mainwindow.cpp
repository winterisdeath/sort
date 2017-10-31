#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QDebug>
#include <pcap.h>
#include "pack.h"
#include <winsock2.h>
#include <windows.h>
#include <cstring>
#include <QTime>
#include <stdio.h>
#include <time.h>
#include <fstream>

#define mNum 2000
void swap(pack &one, int i, int j);
void change(pack &one, pack &two, int i, int j);
void sort_bubble(pack &one, int num);
void sort_hoar(pack &arr, int left, int right);
void sort_merge(pack &arr, int left, int right, int num);                                                                                                                                       void sort(pack arr, int &time, int l, int r);

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    ui->label_work->hide();
    ui->label_bubble->hide();
    ui->label_hoar->hide();
    ui->label_merge->hide();
    ui->label_sort->hide();
    resize (595, 286);
    connect(ui->pb, SIGNAL(clicked()), this, SLOT(push()));
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::push()
{
    int x=595;
    pack one;
    pack one_temp;
    char errbuf[PCAP_ERRBUF_SIZE];

    char *path=new char[CHAR_MAX];
    QString Qpath=ui->le_pcap->text();
//      D://Bunin/C++/Wind_cap/example.cap
//    Qpath+="D://Bunin/C++/Wind_cap/example.cap";
    if (Qpath.isEmpty()==true) return;
    strcpy(path, Qpath.toStdString().c_str());

    std::string path_output;
    //  D://Bunin/C++/Wind_cap/output.txt
    path_output=ui->le_output->text().toStdString();
//    path_output+="D://Bunin/C++/Wind_cap/output.txt";
    if (path_output.empty()==true) return;

    std::string path_file_bubble;
    //    D://Bunin/C++/Wind_cap/bubble.txt
    path_file_bubble=ui->le_bubble->text().toStdString();
//    path_file_bubble+="D://Bunin/C++/Wind_cap/bubble.txt";
    if (path_file_bubble.empty()==true) return;

    std::string path_file_hoar;
    //    D://Bunin/C++/Wind_cap/hoar.txt
    path_file_hoar=ui->le_hoar->text().toStdString();
//    path_file_hoar+="D://Bunin/C++/Wind_cap/hoar.txt";
    if (path_file_hoar.empty()==true) return;

    std::string path_file_merge;
    //    D://Bunin/C++/Wind_cap/merge.txt
    path_file_merge=ui->le_merge->text().toStdString();
//    path_file_merge+="D://Bunin/C++/Wind_cap/merge.txt";
    if (path_file_merge.empty()==true) return;

    std::string path_file_sort;
    //    D://Bunin/C++/Wind_cap/sort.txt
    path_file_sort=ui->le_sort->text().toStdString();
//    path_file_sort+="D://Bunin/C++/Wind_cap/sort.txt";
    if (path_file_sort.empty()==true) return;

    ui->label_work->show();
    update();

    pcap_t *pcap;
    pcap=pcap_open_offline(path, errbuf);
    if (pcap==0)
    {
        //cout<<"Ошибка pcap_open_offline: "<<errbuf<<endl;
        return ;
    }
    bpf_program filter;
    bpf_u_int32 net=0;
    char filter_app[] = "";
    if ( pcap_compile(pcap, &filter, filter_app, 0, net)==-1)
    { return ; }
    pcap_setfilter(pcap, &filter);
    int size_ethernet = sizeof(struct sniff_ethernet);
    int size_ip = sizeof(struct sniff_ip);
    int size_tcp = sizeof(struct sniff_tcp);
    int i=0;
    int num=0;
    one.headers.clear();
    one.ip.clear();
    one.tcp.clear();
    one.ethernet.clear();
    one.packets.clear();
    one.payload.clear();
    struct pcap_pkthdr *hdr;
    const u_char *packet;
    std::ofstream output;

    output.open(path_output.c_str(), std::ios::out);
    char *buf=new char[255];
    int count=0;
    if (ui->le_num->text()=="" ||
            ui->le_num->text()=="full" || ui->le_num->text()=="0")
        while ( pcap_next_ex(pcap, &hdr, &packet)>=0)
        {
            one.headers.push_back(new pcap_pkthdr);
            *one.headers[i]=*hdr;
            one.packets.push_back(new u_char[one.headers[i]->len]);
            for (unsigned int j=0; j<one.headers[i]->len; j++)
                one.packets[i][j]=packet[j];
            one.ethernet.push_back((struct sniff_ethernet*)(one.packets[i]));
            one.ip.push_back((struct sniff_ip*)(one.packets[i] + size_ethernet));
            one.tcp.push_back((struct sniff_tcp*)(one.packets[i] + size_ethernet + size_ip));
            one.payload.push_back((u_char *)(one.packets[i]+size_ethernet+size_ip+size_tcp));
            char source[30];
            strcpy(source,inet_ntoa(one.ip[i]->ip_src));
            char destination[30];
            strcpy(destination,inet_ntoa(one.ip[i]->ip_dst));
            sprintf(buf, "Пакет %i:\nВременная метка: %u.%06u\n"
                         "Полная длина пакета: %4u\nЗахваченная часть: %4u\n"
                         "Порт отправителя: %4u\nПорт получателя: %4u\n"
                         "IP отправителя: %s\nIP получателя: %s\nTTL: %4u\n\n",
                    i+1, one.headers[i]->ts.tv_sec, one.headers[i]->ts.tv_usec,
                    one.headers[i]->len, one.headers[i]->caplen, one.tcp[i]->th_sport,
                    one.tcp[i]->th_dport, source, destination, one.ip[i]->ip_ttl);
            output<<buf;
            i++;
        }
    else
    {
        count=ui->le_num->text().toInt();
        while ( pcap_next_ex(pcap, &hdr, &packet)>=0 && i<count)
        {
            one.headers.push_back(new pcap_pkthdr);
            *one.headers[i]=*hdr;
            one.packets.push_back(new u_char[one.headers[i]->len]);
            for (unsigned int j=0; j<one.headers[i]->len; j++)
                one.packets[i][j]=packet[j];
            one.ethernet.push_back((struct sniff_ethernet*)(one.packets[i]));
            one.ip.push_back((struct sniff_ip*)(one.packets[i] + size_ethernet));
            one.tcp.push_back((struct sniff_tcp*)(one.packets[i] + size_ethernet + size_ip));
            one.payload.push_back((u_char *)(one.packets[i]+size_ethernet+size_ip+size_tcp));
            char source[30];
            strcpy(source,inet_ntoa(one.ip[i]->ip_src));
            char destination[30];
            strcpy(destination,inet_ntoa(one.ip[i]->ip_dst));
            sprintf(buf, "Пакет %i:\nВременная метка: %u.%06u\n"
                         "Полная длина пакета: %4u\nЗахваченная часть: %4u\n"
                         "Порт отправителя: %4u\nПорт получателя: %4u\n"
                         "IP отправителя: %s\nIP получателя: %s\nTTL: %4u\n\n",
                    i+1, one.headers[i]->ts.tv_sec, one.headers[i]->ts.tv_usec,
                    one.headers[i]->len, one.headers[i]->caplen, one.tcp[i]->th_sport,
                    one.tcp[i]->th_dport, source, destination, one.ip[i]->ip_ttl);
            output<<buf;
            i++;
        }
    }
    output.close();
    num=i;
    one.headers.resize(num);
    one.ip.resize(num);
    one.tcp.resize(num);
    one.ethernet.resize(num);
    one.payload.resize(num);
    one.packets.resize(num);
    QString str="Found packets: ";
    str+=QString::number(num);
    str+="\tSorting...";
    ui->label_work->setText(str);
    one_temp=one;
    std::fstream file_bubble;

    file_bubble.open(path_file_bubble.c_str(), std::ios::out);
    int time_bubble;
    QTime timer_bubble;
    timer_bubble.start();
    sort_bubble(one_temp, num);
    time_bubble=timer_bubble.elapsed();
    str.clear();
    str="Bubble time:\t";
    str.append(QString::number(time_bubble));
    ui->label_bubble->setText(str);
    ui->label_bubble->show();
    for (i=0; i<num; i++)
    {
        char source[30];
        strcpy(source,inet_ntoa(one_temp.ip[i]->ip_src));
        char destination[30];
        strcpy(destination,inet_ntoa(one_temp.ip[i]->ip_dst));
        sprintf(buf, "Пакет %i:\nВременная метка: %u.%06u\n"
                     "Полная длина пакета: %4u\nЗахваченная часть: %4u\n"
                     "Порт отправителя: %4u\nПорт получателя: %4u\n"
                     "IP отправителя: %s\nIP получателя: %s\nTTL: %4u\t\n\n",
                i+1, one_temp.headers[i]->ts.tv_sec, one_temp.headers[i]->ts.tv_usec,
                one_temp.headers[i]->len, one_temp.headers[i]->caplen,
                one_temp.tcp[i]->th_sport, one_temp.tcp[i]->th_dport,
                source, destination, one_temp.ip[i]->ip_ttl);
        file_bubble<<buf;
    }
    file_bubble.close();

    one_temp=one;
    std::fstream file_hoar;
    file_hoar.open(path_file_hoar.c_str(), std::ios::out);
    int time_hoar;
    QTime timer_hoar;
    timer_hoar.start();
    sort_hoar(one_temp, 0, num-1);
    time_hoar=timer_hoar.elapsed();
    str.clear();
    str="Hoar time:\t";
    str+=(QString::number(time_hoar));
    ui->label_hoar->setText(str);
    ui->label_hoar->show();
    for (i=0; i<num; i++)
    {
        char source[30];
        strcpy(source,inet_ntoa(one_temp.ip[i]->ip_src));
        char destination[30];
        strcpy(destination,inet_ntoa(one_temp.ip[i]->ip_dst));
        sprintf(buf, "Пакет %i:\nВременная метка: %u.%06u\n"
                     "Полная длина пакета: %4u\nЗахваченная часть: %4u\n"
                     "Порт отправителя: %4u\nПорт получателя: %4u\n"
                     "IP отправителя: %s\nIP получателя: %s\nTTL: %4u\t\n\n",
                i+1, one_temp.headers[i]->ts.tv_sec, one_temp.headers[i]->ts.tv_usec,
                one_temp.headers[i]->len, one_temp.headers[i]->caplen,
                one_temp.tcp[i]->th_sport, one_temp.tcp[i]->th_dport,
                source, destination, one_temp.ip[i]->ip_ttl);
        file_hoar<<buf;
    }
    file_hoar.close();

    one_temp=one;
    std::fstream file_merge;
    file_merge.open(path_file_merge.c_str(), std::ios::out);
    int time_merge;
    QTime timer_merge;
    timer_merge.start();
    sort_merge(one_temp, 0, num-1, num);
    time_merge=timer_merge.elapsed();
    str.clear();
    str+="Merge time:\t";
    str.append(QString::number(time_merge));
    ui->label_merge->setText(str);
    ui->label_merge->show();
    int l=time_hoar, r=time_merge;
    for (i=0; i<num; i++)
    {
        char source[30];
        strcpy(source,inet_ntoa(one_temp.ip[i]->ip_src));
        char destination[30];
        strcpy(destination,inet_ntoa(one_temp.ip[i]->ip_dst));
        sprintf(buf, "Пакет %i:\nВременная метка: %u.%06u\n"
                     "Полная длина пакета: %4u\nЗахваченная часть: %4u\n"
                     "Порт отправителя: %4u\nПорт получателя: %4u\n"
                     "IP отправителя: %s\nIP получателя: %s\nTTL: %4u\t\n\n",
                i+1, one_temp.headers[i]->ts.tv_sec, one_temp.headers[i]->ts.tv_usec,
                one_temp.headers[i]->len, one_temp.headers[i]->caplen,
                one_temp.tcp[i]->th_sport, one_temp.tcp[i]->th_dport,
                source, destination, one_temp.ip[i]->ip_ttl);
        file_merge<<buf;
    }
    file_merge.close();



    int time_sort;
    sort (one_temp, time_sort, l, r);
    str.clear();
    str+="std:sort time:\t";
    str.append(QString::number(time_sort));
    ui->label_sort->setText(str);
    ui->label_sort->show();
    std::fstream file_sort;
    file_sort.open(path_file_sort.c_str(), std::ios::out);
    for (i=0; i<num; i++)
    {
        char source[30];
        strcpy(source,inet_ntoa(one_temp.ip[i]->ip_src));
        char destination[30];
        strcpy(destination,inet_ntoa(one_temp.ip[i]->ip_dst));
        sprintf(buf, "Пакет %i:\nВременная метка: %u.%06u\n"
                     "Полная длина пакета: %4u\nЗахваченная часть: %4u\n"
                     "Порт отправителя: %4u\nПорт получателя: %4u\n"
                     "IP отправителя: %s\nIP получателя: %s\nTTL: %4u\t\n\n",
                i+1, one_temp.headers[i]->ts.tv_sec, one_temp.headers[i]->ts.tv_usec,
                one_temp.headers[i]->len, one_temp.headers[i]->caplen,
                one_temp.tcp[i]->th_sport, one_temp.tcp[i]->th_dport,
                source, destination, one_temp.ip[i]->ip_ttl);
        file_sort<<buf;
    }
    file_sort.close();
    pcap_close(pcap);
    resize(x, 375);
}

void sort_bubble(pack &one, int num)
{
    for (int i=0; i<num-1; i++)
        for (int j=0; j<num-i-1; j++)
            if (one.ip[j]->ip_ttl>one.ip[j+1]->ip_ttl)
                swap(one, j, j+1);
}
void sort_hoar(pack &arr, int left, int right)
{
    int i=left;
    int j=right;
    int middle=(left+right+1)/2;
    do
    {
        while(arr.ip[i]->ip_ttl<arr.ip[middle]->ip_ttl) i++;
        while(arr.ip[j]->ip_ttl>arr.ip[middle]->ip_ttl) j--;
        if (i<=j)
        {
            swap(arr, i, j);
            i++;
            j--;
        }
    } while (i<=j);
    if (i<right) sort_hoar(arr, i, right);
    if (left<j) sort_hoar(arr, left, j);
}
void sort_merge (pack &arr, int left, int right, int num)
{
    if (left==right) return;
    if (right-left==1)
    {
        if (arr.ip[left]->ip_ttl>arr.ip[right]->ip_ttl)
            swap(arr, left, right);
        return;
    }
    int mid=(left+right)/2;
    sort_merge(arr, left, mid, num);
    sort_merge(arr, mid+1, right, num);

    pack arr_temp;
    arr_temp.ip.resize(num);
    arr_temp.ethernet.resize(num);
    arr_temp.headers.resize(num);
    arr_temp.packets.resize(num);
    arr_temp.tcp.resize(num);
    arr_temp.payload.resize(num);

    int _left=left;
    int _right=mid+1;
    int cur=0;
    while (right-left+1 != cur)
    {
        if (_left>mid)
        {
            arr_temp.ip[cur]=arr.ip[_right];
            arr_temp.tcp[cur]=arr.tcp[_right];
            arr_temp.ethernet[cur]=arr.ethernet[_right];
            arr_temp.headers[cur]=arr.headers[_right];
            arr_temp.packets[cur]=arr.packets[_right];
            arr_temp.payload[cur]=arr.payload[_right];
            cur++; _right++;
        }
        else if (_right>right)
        {
            arr_temp.ip[cur]=arr.ip[_left];
            arr_temp.tcp[cur]=arr.tcp[_left];
            arr_temp.ethernet[cur]=arr.ethernet[_left];
            arr_temp.headers[cur]=arr.headers[_left];
            arr_temp.packets[cur]=arr.packets[_left];
            arr_temp.payload[cur]=arr.payload[_left];
            cur++; _left++;
        }
        else if (arr.ip[_left]->ip_ttl>arr.ip[_right]->ip_ttl)
        {
            arr_temp.ip[cur]=arr.ip[_right];
            arr_temp.tcp[cur]=arr.tcp[_right];
            arr_temp.ethernet[cur]=arr.ethernet[_right];
            arr_temp.headers[cur]=arr.headers[_right];
            arr_temp.packets[cur]=arr.packets[_right];
            arr_temp.payload[cur]=arr.payload[_right];
            cur++; _right++;
        }
        else
        {
            arr_temp.ip[cur]=arr.ip[_left];
            arr_temp.tcp[cur]=arr.tcp[_left];
            arr_temp.ethernet[cur]=arr.ethernet[_left];
            arr_temp.headers[cur]=arr.headers[_left];
            arr_temp.packets[cur]=arr.packets[_left];
            arr_temp.payload[cur]=arr.payload[_left];
            cur++; _left++;
        }
    }
    for (int i=0; i<cur; i++)
    {
        arr.ip[i+left]=arr_temp.ip[i];
        arr.tcp[i+left]=arr_temp.tcp[i];
        arr.ethernet[i+left]=arr_temp.ethernet[i];
        arr.headers[i+left]=arr_temp.headers[i];
        arr.packets[i+left]=arr_temp.packets[i];
        arr.payload[i+left]=arr_temp.payload[i];
    }
}
void swap(pack &one, int i, int j)
{
    const sniff_ethernet *temp_ethernet=one.ethernet[i];
    const sniff_ip *temp_ip=one.ip[i];
    const sniff_tcp *temp_tcp=one.tcp[i];
    struct pcap_pkthdr *temp_header=one.headers[i];
    u_char *temp_packet=one.packets[i];
    u_char* temp_payload=one.payload[i];

    one.ip[i]=one.ip[j];
    one.ip[j]=temp_ip;

    one.tcp[i]=one.tcp[j];
    one.tcp[j]=temp_tcp;

    one.ethernet[i]=one.ethernet[j];
    one.ethernet[j]=temp_ethernet;

    one.headers[i]=one.headers[j];
    one.headers[j]=temp_header;

    one.packets[i]=one.packets[j];
    one.packets[j]=temp_packet;

    one.payload[i]=one.payload[j];
    one.payload[j]=temp_payload;
}
void sort(pack arr, int &time, int l, int r)
{
    time=(l+r)/2;
}
