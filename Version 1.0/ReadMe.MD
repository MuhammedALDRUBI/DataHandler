<h1 style="text-align:center;padding:10px;background-color:#333;Color:#fff">DataHandler Class</h1>
<h2>this class helps you to Handle All Data that come from inputs , and you can handle CSRF Token Processes that make your form more protected</h2>

<h3>usable Methodes :</h3>

- Sanitize_Data($Assoc_values_array , $keys_Filters_array)
-  Validate_Data($Assoc_values_array , $keys_Filters_array)
-  hash_password($value_to_hasing , $algorithm = PASSWORD_BCRYPT)
-  check_hashed_password($hashed_password_from_DB , $password_from_input)
-  returnAsJSON($status , $MessagesArray = array() , $data = array() )
-  CreateCSRFToken($expire = 300)
-  CheckCSRFToken($inputValue)

<hr>
1 - Sanitize_Data($Assoc_values_array , $keys_Filters_array)
Sanitize_Data method helps you to filter your data that come with $_POST or any associative array
@param $Assoc_values_array must be an associative array that you want to filter its values
@param $keys_Filters_array must be an associative array that bind each key with its filter
Not : you can use a single sanitize filter for each key and that filter must be find in $usableSanitizeFilters array
<b>this method return $Assoc_values_array after sanitizing is done</b>
ex :
$Assoc_values_array = array("username" => "Muhammed" , "password" => 224422);
$keys_Filters_array = array("username" => "string" , "password" => "password");
DataHandler::Sanitize_Data($Assoc_values_array , $keys_Filters_array);

<hr>

2- Validate_Data($Assoc_values_array , $keys_Filters_array)
Validate_Data method helps you to filter your data that come with $_POST or any associative array
@param $Assoc_values_array must be an associative array that you want to filter its values
@param $keys_Filters_array must be an associative array that bind each key with its filter
Not : you can use multi filter for each key by putting the seperator | between filters but filters must be logically compatible 
and these filter must be find in $usableValidatingFilters array
<b>this method return true or array of error messages</b>

ex : 
$Assoc_values_array = array("Email" => "Muhammed@gmail.com" , "age" => 24);
// min value = 1 , max value = 99 ....... dont use float with int because int is not same as int and you wil get a error message
//now we want to check if Email is valid email and age 's values is integer and its min value = 1 , max value = 99
$keys_Filters_array = array("username" => "email" , "age" => "int(1,99)"); 
DataHandler::Validate_Data($Assoc_values_array , $keys_Filters_array) // if condition true you will get a true else you will get an error Messages array

<hr>

3- hash_password($value_to_hasing , $algorithm = PASSWORD_BCRYPT)

password hashing method ........... that convert your password to hased password
$value_to_hasing it the the value that you want to hash it
hashing algorith is PASSWORD_BCRYPT by default
<b>This method will return the hashed passwod that can you store it in DB</b>
ex : 
$value_to_hasing = 224422;
DataHandler::hash_password($value_to_hasing , $algorithm = PASSWORD_BCRYPT);

<hr>

4- check_hashed_password($hashed_password_from_DB , $password_from_input)
password hashing method ........... that check if your $hashed_password_from_DB is eqiual to hased $password_from_input 
$hashed_password_from_DB that password that come from database after select statment by email is done
$password_from_input is the password that come from login form (from user)
<b>Method will return an logical value (true or false)</b>
ex :
$hashed_password_from_DB = '$2y$10$ck8MWZLLNc8rFa1RVLffjOb75n0Z8aNQdIMeAZKWPkIPK47Ys1OyW';
$password_from_input = 224422;
DataHandler::check_hashed_password($hashed_password_from_DB , $password_from_input);

<hr>

5 - returnAsJSON($status , $MessagesArray = array() , $data = array() )

