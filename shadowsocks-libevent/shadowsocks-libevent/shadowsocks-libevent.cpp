// shadowsocks-libevent.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"

long (*p1)(int);
long (*(*p)(double,int))(int);

long f1(int i)
{
   return 0;
}

typedef long (*FUNC)(int );

FUNC f2(double d,int i )
{
	return f1;
}
long func(double d,int i)
{
	 return 0;
}
int _tmain(int argc, _TCHAR* argv[])
{

	p1 = f1;
	p = f2;
	p1(1);
	return 0;
}

