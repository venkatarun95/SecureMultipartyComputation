#include <cassert>
#include <chrono>
#include <cmath>
#include <iomanip>
#include <iostream>
#include <random>
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

default_random_engine rand_gen;
uniform_real_distribution<double> uniform_rand(0.0,1.0);

// int round(double x) {
// 	if (x >= 0)
// 		return (int) (x + 0.5);
// 	return (int) (x - 0.5);
// }

// double abs(double x) {
// 	if (x > 0)
// 		return x;
// 	return -x;
// }

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

bool intersect(const VectorSet& a, const VectorSet& b) {
	for (const auto& x : a)
		if (b.count(x))
			return true;
	return false;
}

// Return a random vector in [0, 1]^d.
Vector rand_vector(int d) {
	Vector res(d, 0);
	for (int i = 0; i < d; ++i)
		res[i] = uniform_rand(rand_gen);
	return res;
}

// Find norm of a vector.
double norm(const Vector& vec, int l=2) {
	assert(l == 2);
	double res = 0;
	for (const auto& x : vec)
		res += x * x;
	return sqrt(res);
}

void scalar_mult(Vector& vec, double factor) {
	for (int i = 0; i < vec.size(); ++i)
		vec[i] *= factor;
}

// Do a = a + b.
void add_vec(Vector& a, const Vector& b) {
	for (int i = 0; i < a.size(); ++i)
		a[i] += b[i];
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
    if ((int)round(cur[i]) % 2) {
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

int gen_pts(const Vector& center, const double radius, VectorSet& res) {
  Vector cur(center);

  // Convert to one-odd
  for (int i = 0; i < cur.size(); ++i) {
    if ((int)round(cur[i]) % 2)
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

int gen_pts_d(const Vector& center, const double radius, VectorSet& res) {
	Vector cur(center);
	for (int i = 0; i < center.size() * 1; ++i) {
		for (int j = 0; j < cur.size(); ++j)
			cur[j] += 1e3 + 1.0/center.size();
		Vector next(cur);
		for (int j = 0; j < cur.size(); ++j)
			next[j] = int(cur[j] / radius) * radius;
		res.insert(next);
	}
	return res.size();
}

int main() {
	rand_gen.seed(chrono::system_clock::now().time_since_epoch().count());
	
	// Individual Tests
	
	// int dim = 100;
	// double radius = 1.0 / 64.0; //1 * dim;
	// Vector c1 = rand_vector(dim); //(dim, 0.9);
	// VectorSet res;
	// cout << setprecision(4) << gen_pts_d(c1, radius, res) << endl;
	// for (const auto& x : res)
	// 	print_vec(x);

	
	// Test growth with number of dimensions
	
	// for (int dim = 2; dim < 100; ++dim) {
	// 	Vector c1(dim, 2);
	// 	VectorSet res;
	// 	//print_vec(c1);
	// 	double radius = 1.0 / 64;
	// 	cout << dim << " " << radius << " " << gen_pts_d(c1, radius, res) << endl;
	// }


	// Test accuracy

	int dim;
	cin >> dim;
	double radius = 1.0 / 64.0;
	int num_samples = 1000;
	for (double factor = 0.1; factor < 1.55; factor += 0.1) {
		int num_matched = 0;
		for (int sample = 0; sample < num_samples; ++sample) {
			Vector a = rand_vector(dim);
			//scalar_mult(a, 10);
			Vector b = rand_vector(dim);
			scalar_mult(b, factor * radius / norm(b));
			add_vec(b, a);
			
			VectorSet apts, bpts;
			gen_pts_d(a, radius, apts);
			gen_pts_d(b, radius, bpts);
			num_matched += intersect(apts, bpts);
		}
		cout << factor << " " << 1.0 * num_matched / num_samples << endl;
	}
  return 0;
}
