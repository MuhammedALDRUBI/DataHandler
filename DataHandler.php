<?php

//DataHandler v 1.0

//this class helps you to Handle All Data that come from inputs , and you can handle CSRF Token Processes that make your form more protected
class DataHandler{

    //this array will be returned when validation of data is false
    static private $ErrorMessages = array();

    //////////////////////////////////////////////////////////////////////////////////
    //Data Sanitizeing Part - start of part
    //////////////////////////////////////////////////////////////////////////////////

    //the filters are allowed to use in Sanitize_Data method
    static private $usableSanitizeFilters = array("string" , "int" ,  "float" , "email" , "url" , "password");

    //////////////////////////////////////////////////////////////////////////////////
    ////////////////////////////////////////////////////////////////////////////////// 
    // Sanitize_Data method helps you to filter your data that come with $_POST or any associative array
    //@param $Assoc_values_array must be an associative array that you want to filter its values
    //@param $keys_Filters_array must be an associative array that bind each key with its filter
    //Not : you can use a single sanitize filter for each key and that filter must be find in $usableSanitizeFilters array
    //this method return $Assoc_values_array after sanitizing is done
    ///////////////////////////////////////////////////////////////////////////////////
    //////////////////////////////////////////////////////////////////////////////////
    static public function Sanitize_Data($Assoc_values_array , $keys_Filters_array){
        try{
            
            if(isset($Assoc_values_array["submit"])){unset($Assoc_values_array["submit"]);}
            if(isset($Assoc_values_array["CSRF_Token"])){unset($Assoc_values_array["CSRF_Token"]);}
            foreach($keys_Filters_array as $key => $filters_string){
                $filter_for_this_key = explode("|" , $filters_string)[0];

                if(in_array(strtolower($filter_for_this_key) , self::$usableSanitizeFilters)){
                    $method_name_must_be_called = "sanitize_" . $filter_for_this_key . "_fun";
                    $Assoc_values_array[$key] = self::{$method_name_must_be_called}($Assoc_values_array[$key]);
                }else{
                    throw new Exception("Please use a valid filter name for key : " . $key);
                }
            }
            if(empty($Assoc_values_array)){ throw new Exception("No thing has been sanitized");}
            return $Assoc_values_array;
        }
        catch(Exception $e){
            return $e->getMessage();
        }
        

    }


    //alias method for hash_password method ..... that sanitize your password to hased password
    static private function sanitize_password_fun($value_to_sanitize){
        return self::hash_password($value_to_sanitize);
    }
    static private function sanitize_string_fun($value_to_sanitize){
        return filter_var($value_to_sanitize , FILTER_SANITIZE_STRING);
    }
    static private function sanitize_int_fun($value_to_sanitize){
        return filter_var($value_to_sanitize , FILTER_SANITIZE_NUMBER_INT);
    }
    
    static private function sanitize_float_fun($value_to_sanitize){
        return filter_var($value_to_sanitize , FILTER_SANITIZE_NUMBER_FLOAT);
    }
    static private function sanitize_email_fun($value_to_sanitize){
        return filter_var($value_to_sanitize , FILTER_SANITIZE_EMAIL);
    }
    static private function sanitize_url_fun($value_to_sanitize){
        return filter_var($value_to_sanitize , FILTER_SANITIZE_URL);
    } 

    //////////////////////////////////////////////////////////////////////////////////
    //Data Sanitizeing Part - end of part
    //////////////////////////////////////////////////////////////////////////////////

    //--------------------------------------------------------------------------------

    //////////////////////////////////////////////////////////////////////////////////
    //Data validating Part - start of part
    //////////////////////////////////////////////////////////////////////////////////

    //the filters are allowed to use in Validate_Data method
    static private $usableValidatingFilters = array("bool" , "int" ,  "float" , "email" , "url" , "ip");

     //////////////////////////////////////////////////////////////////////////////////
    ////////////////////////////////////////////////////////////////////////////////// 
    // Validate_Data method helps you to filter your data that come with $_POST or any associative array
    //@param $Assoc_values_array must be an associative array that you want to filter its values
    //@param $keys_Filters_array must be an associative array that bind each key with its filter
    //Not : you can use multi filter for each key by putting the seperator | between filters but filters must be logically compatible and these filter must be find in $usableValidatingFilters array
    //this method return true or array of error messages
    ///////////////////////////////////////////////////////////////////////////////////
    //////////////////////////////////////////////////////////////////////////////////
    static public function Validate_Data($Assoc_values_array , $keys_Filters_array){
         
            foreach($keys_Filters_array as $key => $filters_string){
                $filters_for_this_key = explode("|" , $filters_string);

                foreach($filters_for_this_key as $filter ){

                    $options = stripos( $filter , "(") == false ? null : strstr( $filter ,  "(" , false);
                    $filter = stripos( $filter , "(") == false ? $filter : strstr( $filter ,  "(" , true);
                    if(in_array(strtolower($filter) , self::$usableValidatingFilters)){
                        $method_name_must_be_called = "validate_" . $filter . "_fun";
                        $validation_method_result = self::{$method_name_must_be_called}($Assoc_values_array[$key] , $options);
                        if(gettype($validation_method_result) == "string"){
                            self::$ErrorMessages[] = "Validation Error : (key : " . $key . ") "   . $validation_method_result;
                        }
                    }else{
                        self::$ErrorMessages[]  = "(key :" . $key .  ") Please use a valid filter name";
                    }
                }
            }
            
            if(!empty(self::$ErrorMessages)){return self::$ErrorMessages;}
            return true;
    }


    
    static private function validate_url_fun($value_to_validate){
        try{
            $validation_process = filter_var($value_to_validate , FILTER_VALIDATE_URL);
            if(!$validation_process){ throw new Exception("Value is not URL");}
            return true;
        }
        catch(Exception $e){
            return $e->getMessage();
        }
    } 
    static private function validate_email_fun($value_to_validate){
        try{
            $validation_process = filter_var($value_to_validate , FILTER_VALIDATE_EMAIL);
            if(!$validation_process){ throw new Exception("Value is not eamil");}
            return true;
        }
        catch(Exception $e){
            return $e->getMessage();
        }
    } 

    static private function validate_int_fun($value_to_validate , $options = null){
        try{
            $options_array = array();
            if($options != null){    
                $options = trim($options);
                $options = substr($options , 1 , strlen($options) - 2);
                $options_values_array = explode("," , $options);
                $options_array["min_range"] =  intval($options_values_array[0]);
                $options_array["max_range"] =  intval($options_values_array[1]);
                if($value_to_validate < $options_array["min_range"]){throw new Exception("Value is smaller than min-range");}
                if($value_to_validate > $options_array["max_range"]){throw new Exception("Value is larger than min-range");}
            }
            $validation_process = filter_var($value_to_validate , FILTER_VALIDATE_INT , array( "options" => $options_array) );
            if(!$validation_process){ throw new Exception("Value's type is not integer");}
            return true;
        }catch(Exception $e){
            return $e->getMessage();
        }
    } 
    static private function validate_float_fun($value_to_validate , $options = null){
        try{
            $options_array = array();
            if($options != null){    
                $options = trim($options);
                $options = substr($options , 1 , strlen($options) - 2);
                $options_values_array = explode("," , $options);
                $options_array["min_range"] =  intval($options_values_array[0]);
                $options_array["max_range"] =  intval($options_values_array[1]);
                if($value_to_validate < $options_array["min_range"]){throw new Exception("Value is smaller than minimum range");}
                if($value_to_validate > $options_array["max_range"]){throw new Exception("Value is larger than maximum range");}
            }
            $validation_process = filter_var($value_to_validate , FILTER_VALIDATE_FLOAT , array( "options" => $options_array));
            if(! $validation_process){throw new Exception("Value's data type is not float");}
            return true;
        }catch(Exception $e){
            return $e->getMessage();
        }
    } 

    static private function validate_bool_fun($value_to_validate){
        try{
            $validation_process = filter_var($value_to_validate , FILTER_VALIDATE_BOOL);
            if(!$validation_process){ throw new Exception("Value's data type is not Boolean");}
            return true;
        }
        catch(Exception $e){
            return $e->getMessage();
        }
    } 
    static private function validate_ip_fun($value_to_validate){
        try{
            $validation_process = filter_var($value_to_validate , FILTER_VALIDATE_IP);
            if(!$validation_process){ throw new Exception("Value is not IP");}
            return true;
        }
        catch(Exception $e){
            return $e->getMessage();
        }
    } 

    //////////////////////////////////////////////////////////////////////////////////
    //Data validating Part - end of part
    //////////////////////////////////////////////////////////////////////////////////

    //--------------------------------------------------------------------------------

    //////////////////////////////////////////////////////////////////////////////////
    //Data Encryption Part - start of part
    //////////////////////////////////////////////////////////////////////////////////


     //password hashing method ........... that sanitize your password to hased password
     // $value_to_hasing it the the value that you want to hash it
     // hashing algorith is PASSWORD_BCRYPT by default
     static public function hash_password($value_to_hasing , $algorithm = PASSWORD_BCRYPT){
        return password_hash($value_to_hasing , PASSWORD_BCRYPT);
    }

     //password hashing method ........... that check if your $hashed_password_from_DB is eqiual to hased $password_from_input 
     static public function check_hashed_password($hashed_password_from_DB , $password_from_input){
        return password_verify($password_from_input , $hashed_password_from_DB);
    }

    //////////////////////////////////////////////////////////////////////////////////
    //Data Encryption Part - end of part
    //////////////////////////////////////////////////////////////////////////////////  

    //--------------------------------------------------------------------------------

    //////////////////////////////////////////////////////////////////////////////////
    //Data json Part - start of part
    //////////////////////////////////////////////////////////////////////////////////  

    //////////////////////////////////////////////////////////////////////////////////  
    //////////////////////////////////////////////////////////////////////////////////  
    //this method helps you to handle the response of API 
    //$status is the status of process that you did it
    //$MessagesArray is an empty array by default , use it to pass an array of messages that explain waht happened in your process
    // $data is an empty array by default , use it to pass the data to API JSON Object
    //////////////////////////////////////////////////////////////////////////////////  
    //////////////////////////////////////////////////////////////////////////////////  
    static public function returnAsJSON($status , $MessagesArray = array() , $data = array() ){
        $resultArray = array(
            "status" => $status ,
            "Message" => $MessagesArray  ,
            "data" => $data
            
        );
        return json_encode($resultArray);
    }
 
    //////////////////////////////////////////////////////////////////////////////////
    //Data json Part - end of part
    //////////////////////////////////////////////////////////////////////////////////  

    //--------------------------------------------------------------------------------

    //////////////////////////////////////////////////////////////////////////////////
    //CSRF Part - start of part
    //////////////////////////////////////////////////////////////////////////////////  
 
    //////////////////////////////////////////////////////////////////////////////////  
    //////////////////////////////////////////////////////////////////////////////////  
    //this method helps you to Create a CSRF Token and its expires
    //CSRF_Token will be saved in $_SESSION array
    //$expire is an 300 seconds by default (5 minutes) ..... that mean you can generate a CSRF token when you call your form by GET method but you will able to use form for 5 minutes before CSRF Token expire
    // this method return the token that you generated it
    //////////////////////////////////////////////////////////////////////////////////  
    //////////////////////////////////////////////////////////////////////////////////  

    static public function CreateCSRFToken($expire = 300){
        $token = md5(uniqid(rand()));
        if(SessionManager::SaveKeyInSession("CSRF_Token" , $token)){
            SessionManager::SaveKeyInSession("CSRF_Token_time" , time() + $expire);
            return $token;
        }
        return false;
    }

    //this method is private and we use it in CheckCSRFToken method to find CSRF token in Session array 
    static private function getCSRFToken(){
        $token = SessionManager::FindKeyInSession("CSRF_Token");
        return $token;
    }
    //this method is private and we use it in CheckCSRFToken method to find CSRF_Token_time in Session array 
    static private function getCSRFToken_expire(){
        $token_expire = SessionManager::FindKeyInSession("CSRF_Token_time");
        return $token_expire;
    }
    
    //this method is private and we use it in CheckCSRFToken method to remove the CSRF token that expired from session Array
    static private function removeCSRFTokenFromSession(){
        return SessionManager::removeKeyFromSession("CSRF_Token")  && SessionManager::removeKeyFromSession("CSRF_Token_time");
    }

    //////////////////////////////////////////////////////////////////////////////////  
    //////////////////////////////////////////////////////////////////////////////////  
    //this method helps you to Check the CSRF token that come with $_POST array and has been passed as  $inputValue param    
    // this method return true if (CSRF Token that come as $inputValue is eqiual to CSRF Token that found in Session array ) & (Token expire didn't end)
    // and return an error message if conditions are false
    //////////////////////////////////////////////////////////////////////////////////  
    //////////////////////////////////////////////////////////////////////////////////  
    static public function CheckCSRFToken($inputValue){
        $token_from_session = self::getCSRFToken();
        $token_expire_from_session = self::getCSRFToken_expire();
        if($token_from_session != null){ 
            if($token_from_session == $inputValue && ($token_expire_from_session - time() > 0)){
                return true;
            }
            if(self::removeCSRFTokenFromSession()){
                return "CSRF Token has Expired";
            }
            
        }
        return "CSRF Token Is Not Found";
    } 

    //////////////////////////////////////////////////////////////////////////////////
    //CSRF Part - end of part
    //////////////////////////////////////////////////////////////////////////////////  
}