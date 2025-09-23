# This is a documentation of me learning Objective C programming language.

Simple C print function:
```c
    #include <stdio.h>
    int main(){
        printf("This is my first C code, in this tutorial")
    }
```
It is believed to use [Codeblocks](http://www.codeblocks.org/.) and also download the `mingw-setup.exe` which will equip the editor with a compiler.

## Syntax
---
You have already seen the following code a couple of times in the first chapters. Let's break it down to understand it better:

Example:

```c
#include <stdio.h>

int main() {
  printf("Hello World!");
  return 0;
}
```

Example explained: 

> Line 1: `#include <stdio.h>` is a header file library that lets us work with input and output functions, such as **printf()** (used in line 4). Header files add functionality to C programs.

>Line 3: Another thing that always appear in a C program is `main().` **This is called a function.** Any code inside its `curly brackets {}` will be executed.

>Line 4: `printf()` is a function used to output/print text to the screen. In our example, it will output "Hello World!".

```
Note that: Every C statement ends with a semicolon ;
Note: The body of int main() could also been written as:
int main(){printf("Hello World!");return 0;}

Remember: The compiler ignores white spaces. However, multiple lines makes the code more readable.
```

>Line 5: return 0 ends the main() function.

>Line 6: **Do not forget** to add the `closing curly bracket }` to actually end the main function.

# C Statements

A computer program is a list of "instructions" to be "executed" by a computer.

In a programming language, these programming instructions are called statements.

It is important that you end the statement with a semicolon ;

If you forget the semicolon (;), an error will occur and the program will not run:

### Example
```c
printf("Hello World!")
Output
error: expected ';' before 'return'
```

### C Output (Print Text)

Output (Print Text)
To output values or print text in C, you can use the printf() function:

### 
```c
#include <stdio.h>

int main() {
  printf("Hello World!");
  return 0;
}
```

## C New Lines

What is \n exactly?
The newline character (\n) is called an escape sequence, and it forces the cursor to change its position to the beginning of the next line on the screen. This results in a new line.

| Escape Sequence | Description | 
|:-------------   |:--------------:|
|\t               |	Creates a horizontal tab     | 
| \\\             |Inserts a backslash character (\)  | 
|       \\"       | Inserts a double quote character


# Variables
Variables are containers for storing data values, like numbers and characters.

In C, there are different types of variables (defined with different keywords), for example:

**int** - stores integers (whole numbers), <u>without decimals</u>, such as 123 or -123

**float** - stores floating point numbers, with decimals, such as 19.99 or -19.99

**char** - stores single characters, such as 'a' or 'B'. Characters are surrounded by single quotes

## Declaring (Creating) Variables
To create a variable, specify the type and assign it a value:
> Syntax ```type variableName = value; ```
Where type is one of C types (such as int), and variableName is the name of the variable (such as x or myName). The equal sign is used to assign a value to the variable.

So, to create a variable that should store a number, look at the following example:
```c
 Create a variable called myNum of type int and assign the value 15 to it:

 int myNum = 15;
```
You can also declare a variable without assigning the value, and assign the value later:
```c
// Declare a variable
int myNum;

// Assign a value to the variable
myNum = 15;
```
## Output Variables
You learned from the output chapter that you can output values/print text with the printf() function:
```c
Example
printf("Hello World!");
```
In many other programming languages **(like Python, Java, and C++)**, you would normally use a print function to display the value of a variable. However, this is not possible in C:
```c
Example
int myNum = 15;
printf(myNum);  // Nothing happens
```

To output variables in C, you must get familiar with something called **"format specifiers"**, which you will learn about in the next chapter.

# Format Specifiers
Format specifiers are used together with the printf() function to tell the compiler what type of data the variable is storing. ***It is basically a placeholder for the variable value.***

A format specifier starts with a `percentage sign %,` followed by a `character`.

For example, to output the value of an int variable, use the format specifier %d surrounded by double quotes (""), inside the printf() function:
```c
Example
int myNum = 15;
printf("%d", myNum);  // Outputs 15
```
To print other types, use `%c for char` and `%f for float`:
```c
Example
// Create variables
int myNum = 15;            // Integer (whole number)
float myFloatNum = 5.99;   // Floating point number
char myLetter = 'D';       // Character

// Print variables
printf("%d\n", myNum);
printf("%f\n", myFloatNum);
printf("%c\n", myLetter);
```
To combine both text and a variable, separate them with a comma inside the printf() function:
```c
Example
int myNum = 15;
printf("My favorite number is: %d", myNum);
```
To print different types in a single printf() function, you can use the following:
```c
Example
int myNum = 15;
char myLetter = 'D';
printf("My number is %d and my letter is %c", myNum, myLetter);
```
## Print Values Without Variables
You can also just print a value without storing it in a variable, as long as you use the correct format specifier:
```c
Example
printf("My favorite number is: %d", 15);
printf("My favorite letter is: %c", 'D');
```
# Change Variable Values
If you assign a new value to an existing variable, it will overwrite the previous value:
```c
Example
int myNum = 15;  // myNum is 15
myNum = 10;  // Now myNum is 10
```
You can also assign the value of one variable to another:
```c
Example
int myNum = 15;

int myOtherNum = 23;

// Assign the value of myOtherNum (23) to myNum
myNum = myOtherNum;

// myNum is now 23, instead of 15
printf("%d", myNum);
```
Or copy values to empty variables:
```c
Example
// Create a variable and assign the value 15 to it
int myNum = 15;

// Declare a variable without assigning it a value
int myOtherNum;

// Assign the value of myNum to myOtherNum
myOtherNum = myNum;

// myOtherNum now has 15 as a value
printf("%d", myOtherNum);
```
## Add Variables Together
To add a variable to another variable, you can use the + operator:
```c
Example
int x = 5;
int y = 6;
int sum = x + y;
printf("%d", sum);
```
## Declare Multiple Variables
To declare more than one variable of the same type, use a comma-separated list:
```c
Example
int x = 5, y = 6, z = 50;
printf("%d", x + y + z);
```
You can also assign the same value to multiple variables of the same type:
```c
Example
int x, y, z;
x = y = z = 50;
printf("%d", x + y + z);
```
## C Variable Names
All C variables must be identified with unique names.

These unique names are called `identifiers`.

Identifiers can be short names (like x and y) or more descriptive names (age, sum, totalVolume).

Note: It is recommended to use descriptive names in order to create understandable and maintainable code:
```c
Example
// Good variable name
int minutesPerHour = 60;

// OK, but not so easy to understand what m actually is
int m = 60;
```
### The general rules for naming variables are:

* Names can contain letters, digits and underscores
* Names must begin with a letter or an underscore (_)
* Names are case-sensitive (myVar and myvar are different variables)
* Names cannot contain whitespaces or special characters like !, #, %, etc.
* Reserved words (such as int) cannot be used as names

## Real-Life Example
Often in our examples, we simplify variable names to match their data type (myInt or myNum for int types, myChar for char types, and so on). This is done to avoid confusion.

However, for a practical example of using variables, we have created a program that stores different data about a college student:
```c
Example
// Student data
int studentID = 15;
int studentAge = 23;
float studentFee = 75.25;
char studentGrade = 'B';

// Print variables
printf("Student id: %d\n", studentID);
printf("Student age: %d\n", studentAge);
printf("Student fee: %f\n", studentFee);
printf("Student grade: %c", studentGrade);
```
#### Calculate the Area of a Rectangle
In this real-life example, we create a program to calculate the area of a rectangle (by multiplying the length and width):
```c
Example
// Create integer variables
int length = 4;
int width = 6;
int area;

// Calculate the area of a rectangle
area = length * width;

// Print the variables
printf("Length is: %d\n", length);
printf("Width is: %d\n", width);
printf("Area of the rectangle is: %d", area);
```

# C Data Types
## Data Types
As explained in the Variables chapter, a variable in C must be a specified data type, and you must use a format specifier inside the printf() function to display it:
```c
Example
// Create variables
int myNum = 5;             // Integer (whole number)
float myFloatNum = 5.99;   // Floating point number
char myLetter = 'D';       // Character

// Print variables
printf("%d\n", myNum);
printf("%f\n", myFloatNum);
printf("%c\n", myLetter);
```
## Basic Data Types
The data type specifies the size and type of information the variable will store.

In this tutorial, we will focus on the most basic ones:


| Data Type | Size        | Description                                                                 | Example |
|----------|-------------|-----------------------------------------------------------------------------|---------|
| int      | 2 or 4 bytes| Stores whole numbers, without decimals                                     | 1       |
| float    | 4 bytes     | Stores fractional numbers, containing one or more decimals. Sufficient for storing 6-7 decimal digits | 1.99    |
| double   | 8 bytes     | Stores fractional numbers, containing one or more decimals. Sufficient for storing 15 decimal digits | 1.99    |
| char     | 1 byte      | Stores a single character/letter/number, or ASCII values                    | 'A'     |

## Basic Format Specifiers
There are different format specifiers for each data type. Here are some of them:
| Format Specifier | Data Type |
|------------------|-----------|
| %d or %i         | int       |
| %f or %F         | float     |
| %lf              | double    |
| %c              | char      |
| %s              | Used for strings (text), which you will learn more about in a later chapter |

## The char Type
The char data type is used to store a single character.

The character must be surrounded by single quotes, like 'A' or 'c', and we use the %c format specifier to print it:

```c
Example
char myGrade = 'A';
printf("%c", myGrade);
```
Alternatively, if you are familiar with ASCII, you can use ASCII values to display certain characters. Note that these values are not surrounded by quotes (''), as they are numbers:
```c
Example
char a = 65, b = 66, c = 67;
printf("%c", a);
printf("%c", b);
printf("%c", c);
```
Tip: A list of all ASCII values can be found here [ASCII Table Reference.](https://www.ascii-code.com/).
#### Mistakes normally made
### Notes on Characters
If you try to store more than a single character, it will only print the last character:
```c
Example
char myText = 'Hello';
printf("%c", myText);
---
Note: Don't use the char type for storing multiple characters, as it may produce errors.
```
To store multiple characters (or whole words), use strings (which you will learn more about in a later chapter):
```c
Example
char myText[] = "Hello";
printf("%s", myText);
```
## Numeric Types
Use int when you need to store a whole number without decimals, like 35 or 1000, and float or double when you need a floating point number (with decimals), like 9.99 or 3.14515.
```c
int
int myNum = 1000;
printf("%d", myNum);
```
```c
float
float myNum = 5.75;
printf("%f", myNum);
```
```c
double
double myNum = 19.99;
printf("%lf", myNum);
```
> float vs. double
>
>The precision of a floating point value indicates how many digits the value can have after the decimal point. The precision of float is six or seven decimal digits, while double variables have a precision of about 15 digits. Therefore, it is often safer to use double for most calculations - but note that it takes up twice as much memory as float (8 bytes vs. 4 bytes).

## C The sizeof Operator
### Get the Memory Size
We introduced in the data types chapter that the memory size of a variable varies depending on the type:
| Data Type | Size        |
|-----------|-------------|
| int       | 2 or 4 bytes|
| float     | 4 bytes     |
| double    | 8 bytes     |
| char      | 1 byte      |
The memory size refers to how much space a type occupies in the ***computer's memory***.
To actually get the size (in bytes) of a data type or variable, use the sizeof operator:
```c
Example
int myInt;
float myFloat;
double myDouble;
char myChar;

printf("%zu\n", sizeof(myInt));
printf("%zu\n", sizeof(myFloat));
printf("%zu\n", sizeof(myDouble));
printf("%zu\n", sizeof(myChar));
```
>Note that we use the `%zu` format specifier to print the result, instead of `%d`. This is because the compiler expects the `sizeof operator to return a value of type size_t`, which is an ***unsigned integer type***. On some computers it might work with %d, but it is safer and more portable to use `%zu`, which is specifically designed for `printing size_t values`.

>Why Should I Know the Size of Data Types?
***Knowing the size of data types helps you understand how much memory your program uses***. This is important when writing larger programs or working with limited memory, because it can affect both performance and efficiency.

>`For example, the size of a char type is 1 byte. Which means if you have an array of 1000 char values, it will occupy 1000 bytes (1 KB) of memory.`

>Using the right data type for the right purpose will save memory and improve the performance of your program.

>You will learn more about the sizeof operator later in this tutorial, and how to use it in different scenarios.
Real-Life Example
Here's a real-life example of using different data types, to calculate and output the total cost of a number of items:
```c
Example
// Create variables of different data types
int items = 50;
float cost_per_item = 9.99;
float total_cost = items * cost_per_item;
char currency = '$';

// Print variables
printf("Number of items: %d\n", items);
printf("Cost per item: %.2f %c\n", cost_per_item, currency);
printf("Total cost = %.2f %c\n", total_cost, currency);
```
## Type Conversion
Sometimes, you have to convert the value of one data type to another type. This is known as type conversion.

For example, if you try to divide two integers, 5 by 2, you would expect the result to be 2.5. But since we are working with integers (and not floating-point values), the following example will just output 2:
```c
Example
int x = 5;
int y = 2;
int sum = 5 / 2;

printf("%d", sum); // Outputs 2
```
To get the right result, you need to know how type conversion works.

There are two types of conversion in C:

**Implicit Conversion** (automatically)
**Explicit Conversion** (manually)
### Implicit Conversion
Implicit conversion is done automatically by the compiler when you assign a value of one type to another.

For example, if you assign an int value to a float type:
```c
Example
// Automatic conversion: int to float
float myFloat = 9;

printf("%f", myFloat); // 9.000000
```
What happened to .99? We might want that data in our program! So be careful. It is important that you know how the compiler work in these situations, to avoid unexpected results.

As another example, if you divide two integers: 5 by 2, you know that the sum is 2.5. And as you know from the beginning of this page, if you store the sum as an integer, the result will only display the number 2. Therefore, it would be better to store the sum as a float or a double, right?
```c
Example
float sum = 5 / 2;

printf("%f", sum); // 2.000000
```
Why is the result 2.00000 and not 2.5? `Well, it is because 5 and 2 are still integers in the division. In this case, you need to manually convert the integer values to floating-point values`. (see below).

### Explicit Conversion
Explicit conversion is done manually by placing the type in parentheses () in front of the value.

Considering our problem from the example above, we can now get the right result:
```c
Example
// Manual conversion: int to float
float sum = (float) 5 / 2;

printf("%f", sum); // 2.500000
```
You can also place the type in front of a variable:
```c
Example
int num1 = 5;
int num2 = 2;
float sum = (float) num1 / num2;

printf("%f", sum); // 2.500000
```
And since you learned about "decimal precision" in the previous chapter, you could make the output even cleaner by removing the extra zeros (if you like):
```c
Example
int num1 = 5;
int num2 = 2;
float sum = (float) num1 / num2;

printf("%.1f", sum); // 2.5
```
## Real-Life Example
Here's a real-life example of data types and type conversion where we create a program to calculate the percentage of a user's score in relation to the maximum score in a game:
```c
Example
// Set the maximum possible score in the game to 500
int maxScore = 500;

// The actual score of the user
int userScore = 423;

/* Calculate the percantage of the user's score in relation to the maximum available score.
Convert userScore to float to make sure that the division is accurate */
float percentage = (float) userScore / maxScore * 100.0;

// Print the percentage
printf("User's percentage is %.2f", percentage);
```
# C Constants
If you don't want others (or yourself) to change existing variable values, you can use the const keyword.

This will declare the variable as "constant", which means unchangeable and read-only:
```c
Example
const int myNum = 15;  // myNum will always be 15
myNum = 10;  // error: assignment of read-only variable 'myNum'
```
You should always declare the variable as constant when you have values that are unlikely to change:
```c
Example
const int minutesPerHour = 60;
```
## Notes On Constants
When you declare a constant variable, it must be assigned with a value:
```c
Example
Like this:

const int minutesPerHour = 60;
```
```c
This however, will not work:

const int minutesPerHour;
minutesPerHour = 60; // error
```
## Good Practice
Another thing about constant variables, is that it is considered good practice to declare them with uppercase.

It is not required, but useful for code readability and common for C programmers:
```c
Example
const int BIRTHYEAR = 1980;
```
# C Operators
Operators are used to perform operations on variables and values.

C divides the operators into the following groups:

* Arithmetic operators
* Assignment operators
* Comparison operators
* Logical operators
* Bitwise operators

## Arithmetic Operators
Arithmetic operators are used to perform common mathematical operations.

| Operator | Name          | Description                          | Example |
|---------|---------------|--------------------------------------|---------|
| +       | Addition      | Adds together two values             | x + y   |        |
| -       | Subtraction   | Subtracts one value from another     | x - y   |        |
| *       | Multiplication| Multiplies two values                | x * y   |        |
| /       | Division      | Divides one value by another         | x / y   |        |
| %       | Modulus       | Returns the division remainder       | x % y   |        |
| ++      | Increment     | Increases the value of a variable by 1 | ++x   |        |
| --      | Decrement     | Decreases the value of a variable by 1 | --x   |        |

**Note**: `When dividing two integers in C, the result will also be an integer. For example, 10 / 3 gives 3. If you want a decimal result, use float or double values, like 10.0 / 3.`
```c
Example
int a = 10;
int b = 3;
printf("%d\n", a / b);   // Integer division, result is 3

double c = 10.0;
double d = 3.0;
printf("%f\n", c / d);   // Decimal division, result is 3.333...
```
## Assignment Operators
Assignment operators are used to assign values to variables.

In the example below, we use the assignment operator (=) to assign the value 10 to a variable called x:
```c
Example
int x = 10;
```
A list of all assignment operators:

| Operator | Example   | Same As    |
|---------|-----------|-----------|
| =       | x = 5     | x = 5     |
| +=      | x += 3    | x = x + 3 |
| -=      | x -= 3    | x = x - 3 |
| *=      | x *= 3    | x = x * 3 |
| /=      | x /= 3    | x = x / 3 |
| %=      | x %= 3    | x = x % 3 |
| &=      | x &= 3    | x = x & 3 |
| \|=     | x \|= 3   | x = x \| 3 |
| ^=      | x ^= 3    | x = x ^ 3 |
| >>=     | x >>= 3   | x = x >> 3|
| <<=     | x <<= 3   | x = x << 3|

## Comparison Operators
Comparison operators are used to compare two values (or variables). This is important in programming, because it helps us to find answers and make decisions.

>The return value of a comparison is either 1 or 0, which means true (1) or false (0). These values are known as Boolean values, and `you will learn more about them in the Booleans and If..Else chapter.`

In the following example, we use the greater than operator (>) to find out if 5 is greater than 3:
```c
Example
int x = 5;
int y = 3;
printf("%d", x > y); // returns 1 (true) because 5 is greater than 3
```
A list of all comparison operators:
| Operator | Name                      | Example | Description                                                        |
|---------|---------------------------|---------|--------------------------------------------------------------------|
| ==      | Equal to                 | x == y | Returns 1 if the values are equal                                 |
| !=      | Not equal                | x != y | Returns 1 if the values are not equal                             |
| >       | Greater than              | x > y  | Returns 1 if the first value is greater than the second value     |
| <       | Less than                | x < y  | Returns 1 if the first value is less than the second value        |
| >=      | Greater than or equal to | x >= y | Returns 1 if the first value is greater than, or equal to, the second value |
| <=      | Less than or equal to    | x <= y | Returns 1 if the first value is less than, or equal to, the second value |
## Logical Operators
As with comparison operators, you can also test for true or false values with logical operators.

Logical operators are used to determine the logic between variables or values, by combining multiple conditions:
| Operator | Name | Example              | Description                                      |
|----------|------|--------------------|--------------------------------------------------|
| &&       | AND  | x < 5 && x < 10    | Returns 1 if both statements are true            |
| \|\|     | OR   | x < 5 \|\| x < 4   | Returns 1 if one of the statements is true       |
| !        | NOT  | !(x < 5 && x < 10) | Reverses the result, returns 0 if the result is 1|

## Real-Life Example: Login Check
The example below shows how logical operators can be used in a real situation, e.g. when checking login status and access rights:
```c
Example
bool isLoggedIn = true;
bool isAdmin = false;

printf("Regular user: %s\n", (isLoggedIn && !isAdmin) ? "true" : "false");
printf("Has access: %s\n", (isLoggedIn || isAdmin) ? "true" : "false");
printf("Not logged in: %s\n", (!isLoggedIn) ? "true" : "false");
Result:

Regular user: true
Has access: true
Not logged in: false
```
# Booleans
Very often, in programming, you will need a data type that can only have one of two values, like:

* YES / NO
* ON / OFF
* TRUE / FALSE
For this, C has a bool data type, which is known as booleans.

Booleans represent one of two values: true or false.

## Boolean Variables
In C, the bool type is not a built-in data type, like int or char.

It was introduced in C99, and you must import the following header file to use it:

```c
#include <stdbool.h>
```

A boolean variable is declared with the bool keyword and can take the values true or false:
```c
bool isProgrammingFun = true;
bool isFishTasty = false;
```
`Before trying to print the boolean variables, you should know that boolean values are returned as integers`:

1 (or any other number that is not 0) represents true
0 represents false
Therefore, you must use the %d format specifier to print a boolean value:
```c
Example
// Create boolean variables
bool isProgrammingFun = true;
bool isFishTasty = false;

// Return boolean values
printf("%d", isProgrammingFun);   // Returns 1 (true)
printf("%d", isFishTasty);        // Returns 0 (false)
```
However, it is more common to return a boolean value by comparing values and variables.

## omparing Values and Variables
Comparing values are useful in programming, because it helps us to find answers and make decisions.

For example, you can use a comparison operator, such as the greater than (>) operator, to compare two values:
```c
Example
printf("%d", 10 > 9);  // Returns 1 (true) because 10 is greater than 9
```
## Real Life Example
Let's think of a "real life example" where we need to find out if a person is old enough to vote.

In the example below, we use the >= comparison operator to find out if the age (25) is greater than OR equal to the voting age limit, which is set to 18:
```c
Example
int myAge = 25;
int votingAge = 18;

printf("%d", myAge >= votingAge); // Returns 1 (true), meaning 25 year olds are allowed to vote!
```
Cool, right? An even better approach (since we are on a roll now), would be to wrap the code above in an if...else statement, so we can perform different actions depending on the result:

>Example
Output "Old enough to vote!" if myAge is greater than or equal to 18. Otherwise output "Not old enough to vote.":
```c
int myAge = 25;
int votingAge = 18;

if (myAge >= votingAge) {
  printf("Old enough to vote!");
} else {
  printf("Not old enough to vote.");
}
```
# C If ... Else
## Conditions and If Statements
You already know that C supports familiar comparison conditions from mathematics, such as:

>Less than: a < b
Less than or equal to: a <= b
Greater than: a > b
Greater than or equal to: a >= b
Equal to a == b
Not Equal to: a != b
You can use these conditions to perform different actions for different decisions.

C has the following conditional statements:

Use if to specify a block of code to be executed, if a specified condition is true
Use else to specify a block of code to be executed, if the same condition is false
Use else if to specify a new condition to test, if the first condition is false
Use switch to specify many alternative blocks of code to be executed
The if Statement
Use the if statement to specify a block of code to be executed if a condition is true.
```c
Syntax
if (condition) {
  // block of code to be executed if the condition is true
}
```
Note that if is in lowercase letters. Uppercase letters (If or IF) will generate an error.

In the example below, we test two values to find out if 20 is greater than 18. If the condition is true, print some text:
```c
Example
if (20 > 18) {
  printf("20 is greater than 18");
}
We can also test variables:

Example
int x = 20;
int y = 18;
if (x > y) {
  printf("x is greater than y");
}
```
Example explained
In the example above we use two variables, x and y, to test whether x is greater than y (using the > operator). As x is 20, and y is 18, and we know that 20 is greater than 18, we print to the screen that "x is greater than y".

# C Else
## The else Statement
Use the else statement to specify a block of code to be executed if the condition is false.
```c
Syntax
if (condition) {
  // block of code to be executed if the condition is true
} else {
  // block of code to be executed if the condition is false
}
```
```c
Example
int time = 20;
if (time < 18) {
  printf("Good day.");
} else {
  printf("Good evening.");
}
// Outputs "Good evening."
```

Example explained
In the example above, time (20) is greater than 18, so the condition is false. Because of this, we move on to the else condition and print to the screen "Good evening". If the time was less than 18, the program would print "Good day".
# C Else If
## The else if Statement
Use the else if statement to specify a new condition if the first condition is false.
```c
Syntax
if (condition1) {
  // block of code to be executed if condition1 is true
} else if (condition2) {
  // block of code to be executed if the condition1 is false and condition2 is true
} else {
  // block of code to be executed if the condition1 is false and condition2 is false
}
```
```c
Example
int time = 22;
if (time < 10) {
  printf("Good morning.");
} else if (time < 20) {
  printf("Good day.");
} else {
  printf("Good evening.");
}
// Outputs "Good evening."
```
Example explained
In the example above, time (22) is greater than 10, so the first condition is false. The next condition, in the else if statement, is also false, so we move on to the else condition since condition1 and condition2 is both false - and print to the screen "Good evening".

However, if the time was 14, our program would print "Good day."
# C Short Hand If Else
## Short Hand If...Else (Ternary Operator)
There is also a short-hand if else, which is known as the ternary operator because it consists of three operands. It can be used to replace multiple lines of code with a single line. It is often used to replace simple if else statements:
```c
Syntax
variable = (condition) ? expressionTrue : expressionFalse;
Instead of writing:

Example
int time = 20;
if (time < 18) {
  printf("Good day.");
} else {
  printf("Good evening.");
}
```
You can simply write:
```c
Example
int time = 20;
(time < 18) ? printf("Good day.") : printf("Good evening.");
```
It is completely up to you if you want to use the traditional if...else statement or the ternary operator.
# C If ... Else Examples
## Real-Life Examples
This example shows how you can use if..else to "open a door" if the user enters the correct code:
```c
Example
int doorCode = 1337;

if (doorCode == 1337) {
  printf("Correct code.\nThe door is now open.");
} else {
  printf("Wrong code.\nThe door remains closed.");
}
```
Real-Life Examples
This example shows how you can use if..else to "open a door" if the user enters the correct code:
```c
Example
int doorCode = 1337;

if (doorCode == 1337) {
  printf("Correct code.\nThe door is now open.");
} else {
  printf("Wrong code.\nThe door remains closed.");
}
```
Find out if a person is old enough to vote:
```c
Example
int myAge = 25;
int votingAge = 18;

if (myAge >= votingAge) {
  printf("Old enough to vote!");
} else {
  printf("Not old enough to vote.");
}
```
Find out if a number is even or odd:
```c
Example
int myNum = 5;

if (myNum % 2 == 0) {
  printf("%d is even.\n", myNum);
} else {
  printf("%d is odd.\n", myNum);
}
```
# C Switch
## Switch Statement
Instead of writing many if..else statements, you can use the switch statement.

The switch statement selects one of many code blocks to be executed:
```c
Syntax
switch (expression) {
  case x:
    // code block
    break;
  case y:
    // code block
    break;
  default:
    // code block
}
```
This is how it works:

The switch expression is evaluated once
The value of the expression is compared with the values of each case
If there is a match, the associated block of code is executed
The break statement breaks out of the switch block and stops the execution
The default statement is optional, and specifies some code to run if there is no case match
The example below uses the weekday number to calculate the weekday name:
```c
Example
int day = 4;

switch (day) {
  case 1:
    printf("Monday");
    break;
  case 2:
    printf("Tuesday");
    break;
  case 3:
    printf("Wednesday");
    break;
  case 4:
    printf("Thursday");
    break;
  case 5:
    printf("Friday");
    break;
  case 6:
    printf("Saturday");
    break;
  case 7:
    printf("Sunday");
    break;
}

// Outputs "Thursday" (day 4)
```
## The break Keyword
When C reaches a `break` keyword, it breaks out of the switch block.

This will stop the execution of more code and case testing inside the block.

When a match is found, and the job is done, it's time for a break. There is no need for more testing.

>A break can save a lot of execution time because it "ignores" the execution of all the rest of the code in the switch block.

## The default Keyword
The default keyword specifies some code to run if there is no case match:
```c
Example
int day = 4;

switch (day) {
  case 6:
    printf("Today is Saturday");
    break;
  case 7:
    printf("Today is Sunday");
    break;
  default:
    printf("Looking forward to the Weekend");
}

// Outputs "Looking forward to the Weekend"
```
**Note**: The default keyword must be used as the last statement in the switch, and it does not need a break.
# C While Loop
## Loops
Loops can execute a block of code as long as a specified condition is reached.

Loops are handy because they save time, reduce errors, and they make code more readable.

### While Loop
The while loop loops through a block of code as long as a specified condition is true:
```c
Syntax
while (condition) {
  // code block to be executed
}
```
In the example below, the code in the loop will run, over and over again, as long as a variable (i) is less than 5:
```c
Example
int i = 0;

while (i < 5) {
  printf("%d\n", i);
  i++;
}
```
>**Note:** Do not forget to increase the variable used in the condition (i++), otherwise the loop will never end!

>Do you wonder why we use the letter i as a variable name?**It's a counter variable and a common choice in simple loops because it's short, traditional, and stands for 'index' or 'iterator'.**
## Countdown Example
This example counts down from 3 to 1 and then displays "Happy New Year!!" at the end:
```c
Example
int countdown = 3;

while (countdown > 0) {
  printf("%d\n", countdown);
  countdown--;
}
printf("Happy New Year!!\n");
```
# C Do/While Loop
## The Do/While Loop
The do/while loop is a variant of the while loop. This loop will execute the code block once, before checking if the condition is true, then it will repeat the loop as long as the condition is true.
```c
Syntax
do {
  // code block to be executed
}
while (condition);
```
The example below uses a do/while loop. The loop will always be executed at least once, even if the condition is false, because the code block is executed before the condition is tested:
```c
Example
int i = 0;

do {
  printf("%d\n", i);
  i++;
}
while (i < 5);
```
>Do not forget to increase the variable used in the condition, otherwise the loop will never end!
## Condition is False from the Start
In the example above, the condition `i < 5` was **true** at the beginning, so the loop executed multiple times. But what if the condition is **false** right from the start?

In the example below, the variable `i` starts at `10,` so the condition` i < 5 `is false immediately - yet the `do/while` loop still runs once:
```c
Example
Even if the condition is false from the start, the code block will still execute one time:

int i = 10;

do {
  printf("i is %d\n", i);
  i++;
} while (i < 5);
```

>### Summary
>`The do/while loop always runs at least once, even if the condition is already false.` This is different from a regular while loop, which would skip the loop entirely if the condition is false at the start.

>***This behavior makes do/while useful when you want to ensure something happens at least once, like showing a message or asking for user input.***

### Practical Example: User Input
This example keeps asking the user to enter a positive number. The loop stops when the user enters 0 or a negative number:
```c
Example
int number;

do {
  printf("Enter a positive number: ");
  scanf("%d", &number);
} while (number > 0);
```
Note: You will learn more about the `scanf() `function and user input in a later chapter.
# C While Loop Examples
## Real-Life Examples
To demonstrate a practical example of the while loop, we have created a simple "countdown" program:
```c
Example
int countdown = 3;

while (countdown > 0) {
  printf("%d\n", countdown);
  countdown--;
}

printf("Happy New Year!!\n");
```
In this example, we create a program that only print even numbers between 0 and 10 (inclusive):
```c
Example
int i = 0;

while (i <= 10) {
  printf("%d\n", i);
  i += 2;
}
```
In this example we use a while loop to reverse some numbers:
```c
Example
// A variable with some specific numbers
int numbers = 12345;

// A variable to store the reversed number
int revNumbers = 0;

// Reverse and reorder the numbers
while (numbers) {
  // Get the last number of 'numbers' and add it to 'revNumber'
  revNumbers = revNumbers * 10 + numbers % 10;
  // Remove the last number of 'numbers'
  numbers /= 10;
}
```
To demonstrate a practical example of the while loop combined with an if else statement, let's say we play a game of Yatzy:
```c
Example
Print "Yatzy!" If the dice number is 6:

int dice = 1;

while (dice <= 6) {
  if (dice < 6) {
    printf("No Yatzy\n");
  } else {
    printf("Yatzy!\n");
  }
  dice = dice + 1;
}
```
If the loop passes the values ranging from 1 to 5, it prints "No Yatzy". Whenever it passes the value 6, it prints "Yatzy!".

# C For Loop
## For Loop
When you know exactly how many times you want to loop through a block of code, use the for loop instead of a while loop:
```c
Syntax
for (expression 1; expression 2; expression 3) {
  // code block to be executed
}
```
* **Expression 1**  is executed (one time) before the execution of the code block.

* **Expression 2** defines the condition for executing the code block.

- **Expression 3** is executed (every time) after the code block has been executed.

### Print Numbers
The example below will print the numbers 0 to 4:
```c
Example
int i;

for (i = 0; i < 5; i++) {
  printf("%d\n", i);
}
```
### Example explained

* Statement 1 sets a variable before the loop starts: `int i = 0`

* Statement 2 defines the condition for the loop to run: `i < 5.` If the condition is true, the loop will start over again, if it is false, the loop will end.

* Statement 3 increases a value each time the code block in the loop has been executed: `i++`

### Print Even Numbers
This example prints even values between 0 and 10:
```c
Example
int i;

for (i = 0; i <= 10; i = i + 2) {
  printf("%d\n", i);
}
```
### Sum of Numbers
This example calculates the sum of numbers from 1 to 5:
```c
Example
int sum = 0;
int i;

for (i = 1; i <= 5; i++) {
  sum = sum + i;
}

printf("Sum is %d", sum);
```
### Countdown
This example prints a countdown from 5 to 1:
```c
Example
int i;

for (i = 5; i > 0; i--) {
  printf("%d\n", i);
}
```
# C Nested Loops
## Nested Loops
`It is also possible to place a loop inside another loop. This is called a nested loop.`

The "inner loop" will be executed one time for each iteration of the "outer loop":
```c
Example
int i, j;

// Outer loop
for (i = 1; i <= 2; ++i) {
  printf("Outer: %d\n", i);  // Executes 2 times

  // Inner loop
  for (j = 1; j <= 3; ++j) {
    printf(" Inner: %d\n", j);  // Executes 6 times (2 * 3)
  }
}
```
### Multiplication Table Example
This example uses nested loops to print a simple multiplication table (1 to 3):
```c
Example
int i, j;

for (i = 1; i <= 3; i++) {
  for (j = 1; j <= 3; j++) {
    printf("%d ", i * j);
  }
  printf("\n");
}
Result

1 2 3
2 4 6
3 6 9
```
Nested loops are useful when working with tables, matrices, or [multi-dimensional data structures.](https://www.w3schools.com/c/c_arrays_multi.php)
# C For Loop Examples
## Real-Life Examples
To demonstrate a practical example of the for loop, let's create a program that counts to 100 by tens:
```c
Example
for (i = 0; i <= 100; i += 10) {
  printf("%d\n", i);
}
```
In this example, we create a program that only print even numbers between 0 and 10 (inclusive):
```c
Example
for (i = 0; i <= 10; i = i + 2) {
  printf("%d\n", i);
}
```
Here we only print odd numbers:
```c
Example
for (i = 1; i < 10; i = i + 2) {
  printf("%d\n", i);
}
```
In this example we print the powers of 2 up to 512:
```c
Example
for (i = 2; i <= 512; i *= 2) {
  printf("%d\n", i);
}
```
And in this example, we create a program that prints the multiplication table for a specified number:
```c
Example
int number = 2;
int i;

// Print the multiplication table for the number 2
for (i = 1; i <= 10; i++) {
  printf("%d x %d = %d\n", number, i, number * i);
}

return 0;
```
# C Break and Continue
## Break
You have already seen the `break `statement used in an earlier chapter of this tutorial. It was used to "jump out" of a `switch `statement.

The `break `statement can also be used to jump out of a **loop.**

This example jumps out of the **for loop**when `i `is equal to 4:
```c
Example
int i;

for (i = 0; i < 10; i++) {
  if (i == 4) {
    break;
  }
  printf("%d\n", i);
}
```
## Continue
The `continue `statement breaks one iteration (in the loop), if a specified condition occurs, and continues with the next iteration in the loop.

This example skips the value of 4:
```c
Example
int i;

for (i = 0; i < 10; i++) {
  if (i == 4) {
    continue;
  }
  printf("%d\n", i);
}
```
## Break and Continue in While Loop
You can also use break and continue in while loops:
```c
Break Example
int i = 0;

while (i < 10) {
  if (i == 4) {
    break;
  }
  printf("%d\n", i);
  i++;
}
```
## Continue Example
```c
int i = 0;

while (i < 10) {
  if (i == 4) {
    i++;
    continue;
  }
  printf("%d\n", i);
  i++;
}
```
# C Arrays
## Arrays
Arrays are used to store multiple values in a single variable, instead of declaring separate variables for each value.

To create an array, define the data type `(like int)` and specify the name of the array followed by **square brackets [].**

To insert values to it, use a comma-separated list inside curly braces, and make sure all values are of the same data type:
```c
int myNumbers[] = {25, 50, 75, 100};
```
We have now created a variable that holds an array of four integers.

## Access the Elements of an Array
To access an array element, refer to its **index number.**

`Array indexes start with 0: [0] is the first element. [1] is the second element, etc.`

This statement accesses the value of the first element [0] in `myNumbers:`
```c
Example
int myNumbers[] = {25, 50, 75, 100};
printf("%d", myNumbers[0]);

// Outputs 25
```
## Change an Array Element
To change the value of a specific element, refer to the index number:
```c
Example
myNumbers[0] = 33;
```
```c
Example
int myNumbers[] = {25, 50, 75, 100};
myNumbers[0] = 33;

printf("%d", myNumbers[0]);

// Now outputs 33 instead of 25
```
## Loop Through an Array
You can loop through the array elements with the `for` loop.

The following example outputs all elements in the `myNumbers` array:
```c
Example
int myNumbers[] = {25, 50, 75, 100};
int i;

for (i = 0; i < 4; i++) {
  printf("%d\n", myNumbers[i]);
}
```
## Set Array Size
Another common way to create arrays, is to specify the size of the array, and add elements later:
```c
Example
// Declare an array of four integers:
int myNumbers[4];

// Add elements
myNumbers[0] = 25;
myNumbers[1] = 50;
myNumbers[2] = 75;
myNumbers[3] = 100;
```
Using this method, **you should know the number of array elements in advance**, in order for the program to store enough memory.

You are not able to change the size of the array after creation.

## Avoid Mixing Data Types
It is important to note that all elements in an array **must be of the same data type.**

This means you cannot mix different types of values, like integers and floating point numbers, in the same array:
```c
Example
int myArray[] = {25, 50, 75, 3.15, 5.99};
```
In the example above, the values 3.15 and 5.99 will be truncated to 3 and 5. In some cases it might also result in an error, so it is important to always make sure that the elements in the array are of the same type.
# C Array Size
Get Array Size or Length
To get the size of an array, you can use the `sizeof` operator:
```c
Example
int myNumbers[] = {10, 25, 50, 75, 100};
printf("%zu", sizeof(myNumbers)); // Prints 20
```
>Why did the result show` 20 `instead of `5`, when the array contains 5 elements?
- It is because the `sizeof` operator returns the size of a type in **bytes.**

You learned from the [Data Types chapter](https://www.w3schools.com/c/c_data_types.php) that an `int` type is usually 4 bytes, so from the example above, 4 x 5 (4 bytes x 5 elements) = **20 bytes.**

Knowing the memory size of an array is great when you are working with larger programs that require good memory management.

But when you just want to find out how many elements an array has, you can use the following formula (which divides the size of the array by the size of the first element in the array):
```c
Example
int myNumbers[] = {10, 25, 50, 75, 100};
int length = sizeof(myNumbers) / sizeof(myNumbers[0]);

printf("%d", length);  // Prints 5
```
## Making Better Loops
In the [array loops](https://www.w3schools.com/c/c_arrays.php#arrayloop) section in the previous chapter, we wrote the size of the array in the loop condition `(i < 4).` This is not ideal, since it will only work for arrays of a specified size.

However, by using the `sizeof` formula from the example above, we can now make loops that work for arrays of any size, which is more sustainable.

Instead of writing:
```c
Example
int myNumbers[] = {25, 50, 75, 100};
int i;

for (i = 0; i < 4; i++) {
  printf("%d\n", myNumbers[i]);
}
```
It is better to write:
```c
Example
int myNumbers[] = {25, 50, 75, 100};
int length = sizeof(myNumbers) / sizeof(myNumbers[0]);
int i;

for (i = 0; i < length; i++) {
  printf("%d\n", myNumbers[i]);
}
```
# C Arrays - Real-Life Examples
## Real-Life Example
To demonstrate a practical example of using arrays, let's create a program that calculates the average of different ages:
```c
Example
// An array storing different ages
int ages[] = {20, 22, 18, 35, 48, 26, 87, 70};

float avg, sum = 0;
int i;

// Get the length of the array
int length = sizeof(ages) / sizeof(ages[0]);

// Loop through the elements of the array
for (i = 0; i < length; i++) {
  sum += ages[i];
}

// Calculate the average by dividing the sum by the length
avg = sum / length;

// Print the average
printf("The average age is: %.2f", avg);
```
And in this example, we create a program that finds the lowest age among different ages:
```c
Example
// An array storing different ages
int ages[] = {20, 22, 18, 35, 48, 26, 87, 70};

int i;

// Get the length of the array
int length = sizeof(ages) / sizeof(ages[0]);

// Create a variable and assign the first array element of ages to it
int lowestAge = ages[0];

// Loop through the elements of the ages array to find the lowest age
for (i = 0; i < length; i++) {
  if (lowestAge > ages[i]) {
    lowestAge = ages[i];
  }
}
```
# C Multidimensional Arrays
## Multidimensional Arrays
In the previous chapter, you learned about arrays, which is also known as `single dimension arrays. `These are great, and something you will use a lot while programming in C. However, if you want to store data as a tabular form, like a table with rows and columns, you need to get familiar with `multidimensional arrays.`

**A multidimensional array is basically an array of arrays.**

Arrays can have any number of dimensions. In this chapter, we will introduce the most common; two-dimensional arrays (2D).

## Two-Dimensional Arrays
A 2D array is also known as a matrix (a table of rows and columns).

To create a 2D array of integers, take a look at the following example:
```c
int matrix[2][3] = { {1, 4, 2}, {3, 6, 8} };
```
The first dimension represents the number of rows [2], while the second dimension represents the number of columns [3]. The values are placed in row-order, and can be visualized like this:
![visualization](\public\post-images\C\Screenshot 2025-09-22 124342)
## Access the Elements of a 2D Array
To access an element of a two-dimensional array, you must specify the index number of both the row and column.

This statement accesses the value of the element in the **first row (0)** and **third column (2)** of the **matrix array.**
```c
Example
int matrix[2][3] = { {1, 4, 2}, {3, 6, 8} };

printf("%d", matrix[0][2]);  // Outputs 2
```
- **Remember that:** Array indexes start with 0: [0] is the first element. [1] is the second element, etc.
## Change Elements in a 2D Array
To change the value of an element, refer to the index number of the element in each of the dimensions:

The following example will change the value of the element in the **first row (0) and first column (0):**
```c
Example
int matrix[2][3] = { {1, 4, 2}, {3, 6, 8} };
matrix[0][0] = 9;

printf("%d", matrix[0][0]);  // Now outputs 9 instead of 1
```
## Loop Through a 2D Array
To loop through a multi-dimensional array, you need one loop for each of the array's dimensions.

The following example outputs all elements in the **matrix array:**
```c
Example
int matrix[2][3] = { {1, 4, 2}, {3, 6, 8} };

int i, j;
for (i = 0; i < 2; i++) {
  for (j = 0; j < 3; j++) {
    printf("%d\n", matrix[i][j]);
  }
}
```
## Three-Dimensional Arrays
You can also declare arrays with more than two dimensions:
```c
Example
// A 3D array with 2 blocks, each with 4 rows and 3 columns
int example[2][4][3];
```
This creates a 3D array with:

- 2 blocks (first index)
- 4 rows per block (second index)
- 3 columns per row (third index)

## When to Use Multidimensional Arrays
Multidimensional arrays are useful when your data is arranged in rows and columns, like a table, grid, or matrix.

Each extra dimension adds another level of structure:

- 2D arrays (like int scores[3][4]) are great for storing things like scores, game boards, or spreadsheets

- 3D arrays (like int cube[2][3][4]) can represent more complex structures like a set of tables or levels in a game
# C Strings
## Strings
Strings are used for storing text/characters.

For example, "Hello World" is a string of characters.

Unlike many other programming languages, C does not have a String type to easily create string variables. Instead, you must use the char type and create an array of characters to make a string in C:
```c
char greetings[] = "Hello World!";
Note that you have to use double quotes ("").
```
To output the string, you can use the printf() function together with the format specifier %s to tell C that we are now working with strings:
```c
Example
char greetings[] = "Hello World!";
printf("%s", greetings);
```
## Access Strings
Since strings are actually arrays in C, you can access a string by referring to its index number inside square brackets [].

This example prints the **first character (0) in greetings:**
```c
Example
char greetings[] = "Hello World!";
printf("%c", greetings[0]);
```
**Note** that we have to use the %c format specifier to print a **single character.**
# Modify Strings
To change the value of a specific character in a string, refer to the index number, and use **single quotes:**
```c
Example
char greetings[] = "Hello World!";
greetings[0] = 'J';
printf("%s", greetings);
// Outputs Jello World! instead of Hello World!
```
## Loop Through a String
You can also loop through the characters of a string, using a for loop:
```c
Example
char carName[] = "Volvo";
int i;

for (i = 0; i < 5; ++i) {
  printf("%c\n", carName[i]);
}
```
And like we specified in the arrays chapter, you can also use the sizeof formula (instead of manually write the size of the array in the loop condition (i < 5)) to make the loop more sustainable:
```c
Example
char carName[] = "Volvo";
int length = sizeof(carName) / sizeof(carName[0]);
int i;

for (i = 0; i < length; ++i) {
  printf("%c\n", carName[i]);
}
```
## Another Way Of Creating Strings
In the examples above, we used a "string literal" to create a string variable. This is the easiest way to create a string in C.

You should also note that you can create a string with a set of characters. This example will produce the same result as the example in the beginning of this page:
```c
Example
char greetings[] = {'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd', '!', '\0'};
printf("%s", greetings);
```
>**Why do we include the \0 character at the end?** This is known as the "null terminating character", and must be included when creating strings using this method. It tells C that this is the end of the string.

## Differences
The difference between the two ways of creating strings, is that the first method is easier to write, and you do not have to include the \0 character, as C will do it for you.

You should note that the size of both arrays is the same: They both have **13 characters** (space also counts as a character by the way), including the `\0 character:`
```c
Example
char greetings[] = {'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd', '!', '\0'};
char greetings2[] = "Hello World!";

printf("%zu\n", sizeof(greetings));   // Outputs 13
printf("%zu\n", sizeof(greetings2));  // Outputs 13
```
## Real-Life Example
Use strings to create a simple welcome message:
```c
Example
char message[] = "Good to see you,";
char fname[] = "John";

printf("%s %s!", message, fname);
```
# C Special Characters
## Strings - Special Characters
Because strings must be written within quotes, C will misunderstand this string, and generate an error:
```c
char txt[] = "We are the so-called "Vikings" from the north.";
```
The solution to avoid this problem, is to use the backslash escape character.

***The sequence` \" ` inserts a double quote in a string:***
```c
Example
char txt[] = "We are the so-called \"Vikings\" from the north.";
```
The sequence `\' ` inserts a single quote in a string:
```c
Example
char txt[] = "It\'s alright.";
Output 
Its's alright
return 0
```
The sequence` \\ ` inserts a single backslash in a string:
```c
Example
char txt[] = "The character \\ is called backslash.";
```
Other popular escape characters in C are:

Escape Character
- \n	  ---> New Line	
- \t		  ---> Tab	
- \0		  ---> Null

# C String Functions























