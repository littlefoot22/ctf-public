""" 
Python program to print all path from root to 
leaf in a binary tree 
"""

# binary tree node contains data field , 
# left and right pointer 
class Node: 
	# constructor to create tree node 
	def __init__(self, data): 
		self.data = data 
		self.left = None
		self.right = None

# function to print all path from root 
# to leaf in binary tree 
def printPaths(root): 
	# list to store path 
	path = [] 
	printPathsRec(root, path, 0) 

# Helper function to print path from root 
# to leaf in binary tree 
def printPathsRec(root, path, pathLen): 
	
	# Base condition - if binary tree is 
	# empty return 
	if root is None: 
		return

	# add current root's data into 
	# path_ar list 
	
	# if length of list is gre 
	if(len(path) > pathLen): 
		path[pathLen] = root.data 
	else: 
		path.append(root.data) 

	# increment pathLen by 1 
	pathLen = pathLen + 1

	if root.left is None and root.right is None: 
		
		# leaf node then print the list 
		printArray(path, pathLen) 
	else: 
		# try for left and right subtree 
		printPathsRec(root.left, path, pathLen) 
		printPathsRec(root.right, path, pathLen) 

# function to print all path from root 
# to leaf in binary tree 
def xorPaths(root): 
	# list to store path 
	#path = [] 
	#order = []
	xorPathsRec(root, None, 0, "S", None) 

# Helper function to print path from root 
# to leaf in binary tree 
def xorPathsRec(root, path, pathLen, direction, order): 
	if path is None:
		path = []
	if order is None:
		order = []
	# Base condition - if binary tree is 
	# empty return 
	if root is None: 
		xorarray(path, pathLen, order)
		return
	# if its a num append else change root to loop
	if(isinstance(root.data, int)):
		if(len(path) > pathLen): 
			path[pathLen] = root.data
			order[pathLen] = direction
		else: 
			path.append(root.data) 
			order.append(direction) 
		pathLen = pathLen + 1
	else: 
		root = root.data
		if(len(path) > pathLen): 
			path[pathLen] = root.data
			order[pathLen] = direction
		else: 
			path.append(root.data) 
			order.append(direction) 
		#path.append(root.data)
		#order.append(direction) 
		pathLen = pathLen + 1
	# increment pathLen by 1 
	#pathLen = pathLen + 1 14 17 18 19 20 19 17
	if pathLen >= 13:
		xorarray(path, pathLen, order)	
		return	
		#xorarray(path, pathLen, order)
	else:
		xorPathsRec(root.left, path, pathLen, "L", order) 
		xorPathsRec(root.right, path, pathLen, "R", order) 

# xor the array to get the solution
def xorarray(ints, len, order): 
	for i in ints[0 : len]:
		print(hex(i)," ",end="") 
	print()
	curr = 0x47bbfa96
	for i in ints[1 : len]:
		print('i :: ' + hex(i))
		curr = (curr ^ values[i]) 
	print('sol ' + hex(curr)) 
	#if curr == 0x40475194:
		#print(*order)
	for i in order[0 : len]:
		print(i," ",end="") 


# Helper function to print list in which 
# root-to-leaf path is stored 
def printArray(ints, len): 
	for i in ints[0 : len]:
		if isinstance(i, int):
			print(hex(i)," ",end="") 
		else:
			print(" -> loop")
	print() 

# Driver program to test above function 
""" 
Constructed binary tree is  LLLLLLRLRLRL     LLLLLLRLRLRL
			10 
		/ \ 
		8	 2 
	/ \ / 
	3 5 2 
"""
root = Node(0x0804c160) 

root.left = Node(0x0804c19c) 
root.right = Node(0x0804c178)  ######

root.left.left = Node(0x0804c1cc) 
root.left.right = Node(0x0804c214) 
root.right.left = Node(0x0804c1d8) 
root.right.right = Node(0x0804c1a8) #######


root.left.left.left = Node(0x0804c1f0)
root.left.left.right = Node(0x0804c184) 
root.left.right.left = Node(root.left.left) #0x0804c1cc
root.left.right.right = Node(0x0804c1fc)     ##########


root.right.left.left = Node(root.left.right) #0x0804c214
root.right.left.right = Node(0x0804c1c0) #0x0804c1c0
root.right.right.left = Node(root.right) #0x0804c178
root.right.right.right = Node(root.left.left.right) #0x0804c184   ########


root.left.left.left.left = Node(root.left.left.right) #0x0804c184
root.left.left.left.right = Node(root.right) #0x0804c178
root.left.left.right.left = Node(root.left) #0x0804c19c
root.left.left.right.right = Node(root.right.left.right) #0x0804c1c0  #######


root.left.right.right.left = Node(0x0804c190) 
root.left.right.right.right = Node(0x0804c1b4) 
root.right.left.right.left = Node(0x0804c1e4) 
root.right.left.right.right = Node(root.left.left.right) #0x0804c184 ##########


root.left.right.right.left.left = Node(root.left.left.left) #0x0804c1f0
root.left.right.right.left.right = Node(root.left.right.right) #0x0804c1fc
root.left.right.right.right.left = Node(root.left.left) #0x0804c1cc
root.left.right.right.right.right = Node(root.right.right) #0x0804c1a8
root.right.left.right.left.left = Node(root.left) #0x0804c19c
root.right.left.right.left.right = Node(root.right.left.right) #0x0804c1c0


values = {
		0x0804c160 : 0x47bbfa96,
		0x0804c19c : 0x0c4079ef,
		0x0804c1cc : 0x4b846cb6,
		0x0804c1f0 : 0x16848c16,
		0x0804c184 : 0x634284d3,
		0x0804c214 : 0x770ea82a,
		0x0804c1c0 : 0x237a3a88,
		0x0804c178 : 0x23daf3f1,
		0x0804c1e4 : 0x3a4ad3ff,
		0x0804c1d8 : 0x1fba9a98,
		0x0804c190 : 0x344c4eb1,
		0x0804c1fc : 0x499ee4ce,
		0x0804c1a8 : 0x425ebd95,
		0x0804c1b4 : 0x07ace749
	}


#printPaths(root) 
xorPaths(root)
# This code has been contributed by Shweta Singh. 
