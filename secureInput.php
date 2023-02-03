<?php
    function secureInput($input, $attack_mode, $should_strip, $validate_only){
        $sanitized = $input;
        //list char berbahaya untuk serangan sqli, xss, dan rce
        $sqli_charlist = array("'", '"', ";", "-", '#');
        $xss_charlist = array("<",">", "(", ")", ":");
        $rce_charlist = array("`", "|", "&", "$", "@");
        //apabila jenis seranganya all maka semua  array tiap serangan di satukan
        $all_charlist = array_merge($sqli_charlist, $xss_charlist, $rce_charlist);


        //untuk cek apakah dalam input mengandung char berbahaya dengan looping sebanyak panjang input
        for ($i = 0; $i < strlen($input); $i++) {
            //lalu input tiap karater ditampung ke variable
            $char = $input[$i];
            //lalu jika serangan misal SQLI
            if($attack_mode == 'SQLI') {
                //maka karakter saat ini pada input akan dicari di array yang menampung char blacklist sqli
                if (in_array($char, $sqli_charlist)) {
                    //jika karakter tersebut ada maka akan dicek apakah should_strip nya bernilai true
                    if ($should_strip) {
                        //jika iya maka karakter berbahaya tersebut akan direplace dengan '' atau dihapus
                        $sanitized = str_replace($char, '', $sanitized);
                    } else {
                        //jika tidak maka akan diberi \ didepan char tersebut
                        $sanitized = str_replace($char, '\\' . $char, $sanitized);
                    }
                }
                //dan sama halnya juga untuk semua jenis serangan
            } else if($attack_mode == 'XSS') {
                if (in_array($char, $xss_charlist)) {
                    if ($should_strip) {
                        $sanitized = str_replace($char, '', $sanitized);
                    } else {
                        $sanitized = str_replace($char, '\\' . $char, $sanitized);
                    }
                }
            } else if($attack_mode == 'RCE') {
                if (in_array($char, $rce_charlist)) {
                    if ($should_strip) {
                        $sanitized = str_replace($char, '', $sanitized);
                    } else {
                        $sanitized = str_replace($char, '\\' . $char, $sanitized);
                    }
                }
            } else {
                if (in_array($char, $all_charlist)) {
                    if ($should_strip) {
                        $sanitized = str_replace($char, '', $sanitized);
                    } else {
                        $sanitized = str_replace($char, '\\' . $char, $sanitized);
                    }
                }
            } 
        }

        //ini jika validate_only bernilai true
        if($validate_only){
            //maka akan di cek apakah input original dan input sesudah di sanitize bernilai true/sama
            if($sanitized !== $input) {
                //jika beda maka  akan di throw new Exception dengan message sesuai mode serangan
                if($attack_mode === "ALL"){
                    $attack_detect = "SQLI, XSS, RCE";
                } else {
                    $attack_detect = $attack_mode;
                }
                throw new Exception("input constain dangerous token. ".$attack_detect." attack detected, validation failed!!!");
            }
        }

        return $sanitized;
    }

    $input = $_POST['message'];
    //$input = $input = secureInput($input, 'ALL', false, false);
    
    //lalu untuk menangkap error message pada throw new Exception menggunakan try and catch
    try {
        $input = secureInput($input, 'ALL', true, false);
    } catch(Exception $e){
        echo $e->getMessage();
        exit();
    }
    echo $input;

    //apabila lolos maka akan muncul output verification OK
    echo "verification OK";

