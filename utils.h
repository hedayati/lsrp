#ifndef __UTIL_H__
#define __UTIL_H__

#include "lsrp.h"

#define print_mat(mat, row, col)			\
{											\
	int i = 0, j = 0;						\
	printf("\t\t");							\
	for (i = 0; i < row; i++)				\
	{										\
		printf("%s\t", get_name_id(i));		\
	}										\
	printf("\n");							\
	for (i = 0; i < row; i++)				\
	{										\
		printf("%s\t", get_name_id(i));		\
		for(j = 0; j < col; j++)			\
		{									\
			printf("%f\t", mat[i][j]);		\
		}									\
		printf("\n");						\
	}										\
}											\

void dijkstra(int n, int v, double **adj_mat, int *prev)
{
	double dist[n];
	int i;
	int visited[n];
	
	for(i = 0; i < n; i++)
	{
		dist[i] = DBL_MAX;
		prev[i] = -1;
		visited[i] = 0;
	}
	
	dist[v] = 0;
	
	while(1)
	{
		int u = -1;
		double min = DBL_MAX;
		for(i = 0; i < n; i++)
		{
			if(visited[i]) continue;
			if(dist[i] < min)
			{
				min = dist[i];
				u = i;
			}
		}
		if(u == -1)
			break;
		
		visited[u] = 1;
		
		for(i = 0; i < n; i++)
		{
			if(adj_mat[u][i] == 0) continue;
			
			double alt_cost = dist[u] + adj_mat[u][i];
			if(alt_cost < dist[i])
			{
				dist[i] = alt_cost;
				prev[i] = u;
			}
		}
	}
}

int dijkstra_getnext(int v, int *prev)
{
	if(prev[v] == -1) return -1;
	if(prev[prev[v]] == -1) return v;
	
	return dijkstra_getnext(prev[v], prev);
}

#endif
