# Assign 4

SQL Injection

## Tasks

### Bypass the login page using an SQL injection query and log in as “user”

Looking at the app.py we can see the query used for the login (query = f"SELECT * FROM users WHERE username = 'user' AND password = '{password}'")

To exploit that, all we have to do is to append another SQL query like so: smth' OR '1'='1, smth could be any string, by adding OR '1'='1 we append the new query that will be true every time.

The entered query will be: "SELECT * FROM users WHERE username = 'user' AND password = 'smth' OR '1'='1'" (1 = 1 -> true).

### When logged in, use the search functionality to retrieve information from the ‘users’ table instead of ‘items’ and find the “superadmin’s” password and login in to the admin dashboard.

In search() we see that the query is: (query = f"SELECT name,category,price FROM items WHERE name = '{name}'")

In order to get information from users' table instead of items, again we will append a new query like so: smth' UNION SELECT id,username,password FROM users WHERE username = 'superadmin

The entered query will be: "SELECT name,category,price FROM items WHERE name = 'smth' UNION SELECT id,username,password FROM users WHERE username = 'superadmin'".

smth could again be any string, what UNION does is to combine the data from the result of two or more SELECT command queries into a single distinct result set, so by appending the above we get in return is the id username and password for the username superadmin, which was: 1 superadmin sup3r4dm1nP@5sw0rd

The last step is to log in as an admin, to do that we change the http://140.238.219.114:1337/search to http://140.238.219.114:1337/admin, enter the above password, and we are in!

## GCC Version

gcc (Ubuntu 11.3.0-1ubuntu1~22.04) 11.3.0