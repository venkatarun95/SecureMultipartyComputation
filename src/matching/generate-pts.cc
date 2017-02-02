#include <cassert>
#include <iostream>
#include <string>
#include <unordered_set>
#include <vector>

using namespace std;

struct VectorHash {
    size_t operator()(const std::vector<double>& v) const {
        std::hash<double> hasher;
        size_t seed = 0;
        for (double i : v) {
            seed ^= hasher(i) + 0x9e3779b9 + (seed<<6) + (seed>>2);
        }
        return seed;
    }
};

typedef vector<double> Vector;
typedef unordered_set< Vector, VectorHash > VectorSet;

int round(double x) {
	if (x >= 0)
		return (int) (x + 0.5);
	return (int) (x - 0.5);
}

double abs(double x) {
	if (x > 0)
		return x;
	return -x;
}

double dist(const Vector& a, const Vector& b) {
  if (a.size() != b.size())
    throw new string("Attempt to compute distance between vectors of different sizes.");
  double res = 0;
  for (int i = 0; i < a.size(); ++i)
    res += abs(a[i] - b[i]); // * (a[i] - b[i]);    
  return res;
}

void print_vec(const Vector& vec) {
  for (const auto& x : vec)
    cout << x << " ";
  cout << endl;
}

void gen_pts_recur(const Vector& center, Vector& cur, const double radius, VectorSet& visited) {
  assert(center.size() == cur.size());
	if (visited.count(cur))
		return;
	visited.insert(cur);
  //print_vec(cur);
	
  // Explore current even/odd assignment
  for (int i = 0; i < cur.size(); ++i) {
    cur[i] -= 2;
    if (dist(center, cur) < radius)
      gen_pts_recur(center, cur, radius, visited);
    cur[i] += 4;
    if (dist(center, cur) < radius)
      gen_pts_recur(center, cur, radius, visited);
    cur[i] -= 2;
  }

  // Find the odd index
  int odd = -1; // Index which is odd
  for (int i = 0; i < cur.size(); ++i) {
    if (round(cur[i]) % 2) {
      assert(odd == -1);
      odd = i;
    }
	}
  assert(odd != -1);

  // Change even/odd assignment
  cur[odd] += 1;
  for (int i = 0; i < cur.size(); ++i) {
    if (i == odd)
      continue;
    cur[i] -= 1;
    if (dist(center, cur) < radius)
      gen_pts_recur(center, cur, radius, visited);
    cur[i] += 2;
		if (dist(center, cur) < radius)
      gen_pts_recur(center, cur, radius, visited);
		cur[i] -= 1;
  }
  cur[odd] -= 1;

  cur[odd] -= 1;
  for (int i = 0; i < cur.size(); ++i) {
    if (i == odd)
      continue;
    cur[i] -= 1;
    if (dist(center, cur) < radius)
      gen_pts_recur(center, cur, radius, visited);
    cur[i] += 2;
		if (dist(center, cur) < radius)
      gen_pts_recur(center, cur, radius, visited);
		cur[i] -= 1;
  }
  cur[odd] += 1;
}

int gen_pts(const Vector& center, const double radius) {
  Vector cur(center);
	VectorSet res;

  // Convert to one-odd
  for (int i = 0; i < cur.size(); ++i) {
    if (round(cur[i]) % 2)
      cur[i] = (abs(round(cur[i])+1 - cur[i]) <= 1) ? round(cur[i])+1 : round(cur[i])-1;
		else
			cur[i] = round(cur[i]);
	}
	
  cur[0] += 1;
  gen_pts_recur(center, cur, radius, res);
	cur[0] -= 2;
	gen_pts_recur(center, cur, radius, res);
	cur[0] += 1;
	
	return res.size();
}

bool intersect(const VectorSet& a, const VectorSet& b) {
	for (const auto& x : a)
		if (b.count(x))
			return true;
}

int main() {
	// int dim = 5;
	// double radius = 4; //1 * dim;
	// Vector c1(dim, 0.9);
	// cout << gen_pts(c1, radius) << endl;

	for (int dim = 2; dim < 100; ++dim) {
		Vector c1(dim, 2);
		//print_vec(c1);
		double radius = 2;
		cout << dim << " " << radius << " " << gen_pts(c1, radius) << endl;
	}
  return 0;
}
