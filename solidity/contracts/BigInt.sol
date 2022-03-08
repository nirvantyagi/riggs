// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

library BigInt {
    
    struct BigInt {
        bytes val;
        bool neg;
    }

    function from_uint256(uint256 n) internal pure returns(BigInt memory r){
        r.val = abi.encodePacked(n);
    }


    /** @dev prepare_add: Initially prepare bignum instances for addition operation; internally calls actual addition/subtraction, depending on inputs.
      *                   In order to do correct addition or subtraction we have to handle the sign.
      *                   This function discovers the sign of the result based on the inputs, and calls the correct operation.
      *
      * parameter: instance a - first instance
      * parameter: instance b - second instance
      * returns: instance r - addition of a & b.
      */
    function prepare_add(BigInt memory a, BigInt memory b) internal pure returns(BigInt memory r) {
        BigInt memory zero = from_uint256(0);
        bytes memory val;
        int compare = cmp(a, b, false);

        if(a.neg || b.neg) {
            if (a.neg && b.neg) {
                if (compare >= 0) val = bn_add(a.val, b.val);
                else val = bn_add(b.val, a.val);
                r.neg = true;
            }
            else {
                if(compare == 1) {
                    val = bn_sub(a.val, b.val);
                    r.neg = a.neg;
                } else if (compare == -1) {
                    val = bn_sub(b.val, a.val);
                    r.neg = !a.neg;
                } else return zero;
            }
        } else {
            if (compare >= 0) { //a>=b
                val = bn_add(a.val, b.val);
            }
            else {
                val = bn_add(b.val, a.val);
            }
            r.neg = false;
        }

        r.val = val;
    }

    /** @dev bn_add: takes two instance values and the bitlen of the max value, and adds them.
      *              This function is private and only callable from prepare_add: therefore the values may be of different sizes, 
      *              in any order of size, and of different signs (handled in prepare_add).
      *              As values may be of different sizes, inputs are considered starting from the least significant words, working back. 
      *              The function calculates the new bitlen (basically if bitlens are the same for max and min, max_bitlen++) and returns a new instance value.
      *
      * parameter: bytes max -  biggest value  (determined from prepare_add)
      * parameter: bytes min -  smallest value (determined from prepare_add)
      * parameter: uint max_bitlen -  bit length of max value.
      * returns: bytes result - max + min.
      * returns: uint - bit length of result.
      */
    function bn_add(bytes memory max, bytes memory min) private pure returns (bytes memory) {
        bytes memory result;
        assembly {
            let result_start := msize()                                     // Get the highest available block of memory
            let uint_max := sub(0,1)                                        // uint max. achieved using uint underflow: 0xffff...ffff
            let carry := 0
            let max_ptr := add(max, mload(max))
            let min_ptr := add(min, mload(min))                             // point to last word of each byte array.
            let result_ptr := add(add(result_start,0x20), mload(max))         // set result_ptr end.
            for { let i := mload(max) } eq(eq(i,0),0) { i := sub(i, 0x20) } { // for(int i=max_length; i!=0; i-=32)
                let max_val := mload(max_ptr)                               // get next word for 'max'
                switch gt(i,sub(mload(max),mload(min)))                         // if(i>(max_length-min_length)). while 'min' words are still available.
                    case 1{ 
                        let min_val := mload(min_ptr)                       //      get next word for 'min'
                        mstore(result_ptr, add(add(max_val,min_val),carry)) //      result_word = max_word+min_word+carry
                        switch gt(max_val, sub(uint_max,sub(min_val,carry)))     //      this switch block finds whether or not to set the carry bit for the next iteration.
                            case 1  { carry := 1 }
                            default {
                                switch and(eq(max_val,uint_max),or(gt(carry,0), gt(min_val,0)))
                                case 1 { carry := 1 }
                                default{ carry := 0 }
                            }
                        min_ptr := sub(min_ptr,0x20)                       //       point to next 'min' word
                    }
                    default{                                               // else: remainder after 'min' words are complete.
                        mstore(result_ptr, add(max_val,carry))             //       result_word = max_word+carry
                        switch and( eq(uint_max,max_val), eq(carry,1) )         //       this switch block finds whether or not to set the carry bit for the next iteration.
                            case 1  { carry := 1 }
                            default { carry := 0 }
                    }
                result_ptr := sub(result_ptr,0x20)                         // point to next 'result' word
                max_ptr := sub(max_ptr,0x20)                               // point to next 'max' word
            }
            switch eq(carry,0)
                case 1{ result_start := add(result_start,0x20) }           // if carry is 0, increment result_start, ie. length word for result is now one word position ahead.
                default { mstore(result_ptr, 1) }                          // else if carry is 1, store 1; overflow has occured, so length word remains in the same position.
            result := result_start                                         // point 'result' bytes value to the correct address in memory
            mstore(result,add(mload(max),mul(0x20,carry)))                   // store length of result. we are finished with the byte array.
            mstore(0x40, add(result,add(mload(result),0x20)))                // Update freemem pointer to point to new end of memory.
        }
        return result;
    }

    
      /** @dev prepare_sub: Initially prepare bignum instances for addition operation; internally calls actual addition/subtraction, depending on inputs.
      *                   In order to do correct addition or subtraction we have to handle the sign.
      *                   This function discovers the sign of the result based on the inputs, and calls the correct operation.
      *
      * parameter: instance a - first instance
      * parameter: instance b - second instance
      * returns: instance r - a-b.
      */  

    function prepare_sub(BigInt memory a, BigInt memory b) internal pure returns(BigInt memory r) {
        BigInt memory zero = from_uint256(0);
        bytes memory val;
        int compare;
        compare = cmp(a, b, false);
        if(a.neg || b.neg) {
            if(a.neg && b.neg){           
                if(compare == 1) { 
                    val = bn_sub(a.val, b.val);
                    r.neg = true;
                }
                else if(compare == -1) { 
                    val = bn_sub(b.val, a.val);
                    r.neg = false;
                }
                else return zero;
            }
            else {
                if (compare >= 0) val = bn_add(a.val, b.val);
                else val = bn_add(b.val, a.val);
                r.neg = (a.neg) ? true : false;
            }
        }
        else {
            if (compare == 1) {
                val = bn_sub(a.val, b.val);
                r.neg = false;
            } else if (compare == -1) {
                val = bn_sub(b.val, a.val);
                r.neg = true;
            } else return zero;
        }
        r.val = val;
    }


    /** @dev bn_sub: takes two instance values and subtracts them.
      *              This function is private and only callable from prepare_add: therefore the values may be of different sizes, 
      *              in any order of size, and of different signs (handled in prepare_add).
      *              As values may be of different sizes, inputs are considered starting from the least significant words, working back. 
      *              The function calculates the new bitlen (basically if bitlens are the same for max and min, max_bitlen++) and returns a new instance value.
      *
      * parameter: bytes max -  biggest value  (determined from prepare_add)
      * parameter: bytes min -  smallest value (determined from prepare_add)
      * parameter: uint max_bitlen -  bit length of max value.
      * returns: bytes result - max + min.
      * returns: uint - bit length of result.
      */
   function bn_sub(bytes memory max, bytes memory min) private pure returns (bytes memory) {
        bytes memory result;
        uint carry = 0;
        assembly {
            let result_start := msize()                                         // Get the highest available block of memory
            let uint_max := sub(0,1)                                            // uint max. achieved using uint underflow: 0xffff...ffff
            let max_len := mload(max)
            let min_len := mload(min)                                           // load lengths of inputs
            let len_diff := sub(max_len,min_len)                                //get differences in lengths.
            let max_ptr := add(max, max_len)
            let min_ptr := add(min, min_len)                                    //go to end of arrays
            let result_ptr := add(result_start, max_len)                        //point to least significant result word.
            let memory_end := add(result_ptr,0x20)                              // save memory_end to update free memory pointer at the end.
            for { let i := max_len } eq(eq(i,0),0) { i := sub(i, 0x20) } {      // for(int i=max_length; i!=0; i-=32)
                let max_val := mload(max_ptr)                                   // get next word for 'max'
                switch gt(i,len_diff)                                           // if(i>(max_length-min_length)). while 'min' words are still available.
                    case 1{ 
                        let min_val := mload(min_ptr)                           //      get next word for 'min'
                        mstore(result_ptr, sub(sub(max_val,min_val),carry))     //      result_word = (max_word-min_word)-carry
                        switch or(lt(max_val, add(min_val,carry)),
                               and(eq(min_val,uint_max), eq(carry,1)))          //      this switch block finds whether or not to set the carry bit for the next iteration.
                            case 1  { carry := 1 }
                            default { carry := 0 }
                        min_ptr := sub(min_ptr,0x20)                            //      point to next 'result' word
                    }
                    default{                                                    // else: remainder after 'min' words are complete.
                        mstore(result_ptr, sub(max_val,carry))                  //      result_word = max_word-carry
                        switch and( eq(max_val,0), eq(carry,1) )                //      this switch block finds whether or not to set the carry bit for the next iteration.
                            case 1  { carry := 1 }
                            default { carry := 0 }
                    }
                result_ptr := sub(result_ptr,0x20)                              // point to next 'result' word
                max_ptr    := sub(max_ptr,0x20)                                 // point to next 'max' word
            }      

            //the following code removes any leading words containing all zeroes in the result.
            result_ptr := add(result_ptr,0x20)                                                 
            for { }   eq(mload(result_ptr), 0) { result_ptr := add(result_ptr,0x20) } { //for(result_ptr+=32;; result==0; result_ptr+=32)
               result_start := add(result_start, 0x20)                                         // push up the start pointer for the result..
               max_len := sub(max_len,0x20)                                                    // and subtract a word (32 bytes) from the result length.
            } 
            result := result_start                                                              // point 'result' bytes value to the correct address in memory
            mstore(result, max_len)                                                              // store length of result. we are finished with the byte array.
            mstore(0x40, memory_end)                                                            // Update freemem pointer.
        }
        return result;
    }


    /** @dev bn_mul: takes two instances and multiplies them. Order is irrelevant.
      *              multiplication achieved using modexp precompile:
      *                 (a * b) = (((a + b)**2 - (a - b)**2) / 4
      *              squaring is done in op_and_square function.
      *
      * parameter: instance a 
      * parameter: instance b 
      * returns: bytes res = a*b.
      */
    function bn_mul(BigInt memory a, BigInt memory b) internal view returns(BigInt memory res){
        res = op_and_square(a,b,0);                                // add_and_square = (a+b)^2
        //no need to do subtraction part of the equation if a == b; if so, it has no effect on final result.
        if(cmp(a,b,true)!=0){  
            BigInt memory sub_and_square = op_and_square(a,b,1); // sub_and_square = (a-b)^2
            res = prepare_sub(res,sub_and_square);                 // res = add_and_square - sub_and_square
        }
        res = right_shift(res, 2);                                 // res = res / 4
     }


    /** @dev op_and_square: takes two instances, performs operation 'op' on them, and squares the result.
      *                     bn_mul uses the multiplication by squaring method, ie. a*b == ((a+b)^2 - (a-b)^2)/4.
      *                     using modular exponentation precompile for squaring. this requires taking a special modulus value of the form:
      *                     modulus == '1|(0*n)', where n = 2 * bit length of (a 'op' b).
      *
      * parameter: instance a 
      * parameter: instance b 
      * parameter: int op 
      * returns: bytes res - (a'op'b) ^ 2.
      */
    function op_and_square(BigInt memory a, BigInt memory b, int op) private view returns(BigInt memory res){
        BigInt memory two = from_uint256(2);
        uint mod_index = 0;
        uint first_word_modulus;
        bytes memory _modulus;
        
        res = (op == 0) ? prepare_add(a,b) : prepare_sub(a,b); //op == 0: add, op == 1: sub.
        uint res_bitlen = res.val.length * 8;
        assembly { mod_index := mul(res_bitlen,2) }
        first_word_modulus = uint(1) << ((mod_index % 256)); //set bit in first modulus word.
        
        //we pass the minimum modulus value which would return JUST the squaring part of the calculation; therefore the value may be many words long.
        //This is done by:
        //  - storing total modulus byte length
        //  - storing first word of modulus with correct bit set
        //  - updating the free memory pointer to come after total length.
        _modulus = hex"0000000000000000000000000000000000000000000000000000000000000000";
        assembly {
            mstore(_modulus, mul(add(div(mod_index,256),1),0x20))  //store length of modulus
            mstore(add(_modulus,0x20), first_word_modulus)         //set first modulus word
            mstore(0x40, add(_modulus, add(mload(_modulus),0x20))) //update freemem pointer to be modulus index + length
        }

        //create modulus instance for modexp function
        BigInt memory modulus;
        modulus.val = _modulus;
        modulus.neg = false;
        res = prepare_modexp(res,two,modulus); // ((a 'op' b) ^ 2 % modulus) == (a 'op' b) ^ 2.
    }


    function bn_mod(BigInt memory a, BigInt memory mod) internal view returns(BigInt memory res){
        BigInt memory one = from_uint256(1);
        res = prepare_modexp(a, one, mod);
    }


    /** @dev prepare_modexp: takes base, exponent, and modulus, internally computes base^exponent % modulus, and creates new instance.
      *                      this function is overloaded: it assumes the exponent is positive. if not, the other method is used, whereby the inverse of the base is also passed.
      *
      * parameter: instance base 
      * parameter: instance exponent
      * parameter: instance modulus
      * returns: instance result.
      */    
    function prepare_modexp(BigInt memory base, BigInt memory exponent, BigInt memory modulus) internal view returns(BigInt memory result) {
        require(exponent.neg==false); //if exponent is negative, other method with this same name should be used.
        bytes memory _result = modexp(base.val, exponent.val, modulus.val);

        result.val = _result;
        result.neg = (base.neg==false || base.neg && is_odd(exponent)==0) ? false : true;
        return result;
     }

    /** @dev modexp: Takes instance values for base, exp, mod and calls precompile for (_base^_exp)%^mod
      *              Wrapper for built-in modexp (contract 0x5) as described here - https://github.com/ethereum/EIPs/pull/198
      *
      * parameter: bytes base
      * parameter: bytes base_inverse 
      * parameter: bytes exponent
      * returns: bytes ret.
      */
    function modexp(bytes memory _base, bytes memory _exp, bytes memory _mod) private view returns(bytes memory ret) {
        assembly {
            let bl := mload(_base)
            let el := mload(_exp)
            let ml := mload(_mod)

            let freemem := mload(0x40) // Free memory pointer is always stored at 0x40

            mstore(freemem, bl)         // arg[0] = base.length @ +0
            mstore(add(freemem,32), el) // arg[1] = exp.length @ +32
            mstore(add(freemem,64), ml) // arg[2] = mod.length @ +64
            
            // arg[3] = base.bits @ + 96
            // Use identity built-in (contract 0x4) as a cheap memcpy
            let success := staticcall(450, 0x4, add(_base,32), bl, add(freemem,96), bl)
            
            // arg[4] = exp.bits @ +96+base.length
            let size := add(96, bl)
            success := staticcall(450, 0x4, add(_exp,32), el, add(freemem,size), el)
            
            // arg[5] = mod.bits @ +96+base.length+exp.length
            size := add(size,el)
            success := staticcall(450, 0x4, add(_mod,32), ml, add(freemem,size), ml)
            
            switch success case 0 { invalid() } //fail where we haven't enough gas to make the call

            // Total size of input = 96+base.length+exp.length+mod.length
            size := add(size,ml)
            // Invoke contract 0x5, put return value right after mod.length, @ +96
            success := staticcall(sub(gas(), 1350), 0x5, freemem, size, add(96,freemem), ml)

            switch success case 0 { invalid() } //fail where we haven't enough gas to make the call

            // point to the location of the return value (length, bits)
            //assuming mod length is multiple of 32, return value is already in the right format.
            //function visibility is changed to internal to reflect this.
            ret := add(64,freemem)

            mstore(0x40, add(add(96, freemem), ml)) //deallocate freemem pointer
        }
    }


    /** @dev modmul: Takes instances for a, b, and modulus, and computes (a*b) % modulus
      *              We call bn_mul for the two input values, before calling modexp, passing exponent as 1.
      *              Sign is taken care of in sub-functions.
      *
      * parameter: instance a
      * parameter: instance b
      * parameter: instance modulus
      * returns: instance res.
      */
    function modmul(BigInt memory a, BigInt memory b, BigInt memory modulus) internal view returns(BigInt memory res){
        res = bn_mod(bn_mul(a,b),modulus);       
    }


    /** @dev mod_inverse: Takes instances for base, modulus, and result, verifies (base*result)%modulus==1, and returns result.
      *                   Similar to bn_div, it's far cheaper to verify an inverse operation on-chain than it is to calculate it, so we allow the user to pass their own result.
      *
      * parameter: instance base
      * parameter: instance modulus
      * parameter: instance user_result
      * returns: instance user_result.
      */
    function mod_inverse(BigInt memory base, BigInt memory modulus, BigInt memory user_result) internal view returns(BigInt memory){
        require(base.neg==false && modulus.neg==false); //assert positivity of inputs.
        /*
         * the following proves:
         * - user result passed is correct for values base and modulus
         * - modular inverse exists for values base and modulus.
         * otherwise it fails.
         */
        BigInt memory one = from_uint256(1);
        require(cmp(modmul(base, user_result, modulus),one,true)==0);
        return user_result;
     }


    /** @dev is_odd: returns 1 if instance value is an odd number and 0 otherwise.
      *              
      * parameter: instance _in
      * returns: uint ret.
      */  
    function is_odd(BigInt memory _in) internal pure returns(uint ret){
        assembly{
            let in_ptr := add(mload(_in), mload(mload(_in))) //go to least significant word
            ret := mod(mload(in_ptr),2)                      //..and mod it with 2. 
        }
    }


    /** @dev cmp: instance comparison. 'signed' parameter indiciates whether to consider the sign of the inputs.
      *           'trigger' is used to decide this - 
      *              if both negative, invert the result; 
      *              if both positive (or signed==false), trigger has no effect;
      *              if differing signs, we return immediately based on input.
      *           returns -1 on a<b, 0 on a==b, 1 on a>b.
      *           
      * parameter: instance a
      * parameter: instance b
      * parameter: bool signed
      * returns: int.
      */
    function cmp(BigInt memory a, BigInt memory b, bool signed) internal pure returns(int){
        if(b.val.length > a.val.length) return cmp(b, a, signed);
        int trigger = 1;
        if(signed){
            if(a.neg && b.neg) trigger = -1;
            else if(a.neg==false && b.neg==true) return 1;
            else if(a.neg==true && b.neg==false) return -1;
        }

        uint a_len = a.val.length;
        uint b_len = b.val.length;

        uint a_ptr;
        uint b_ptr;
        uint a_word;
        uint b_word;

        for(uint i=0; i < a_len - b_len; i++){
            if (a.val[i] != 0x0) return -1 * trigger;
        }

        assembly{
            a_ptr := add(mload(a),0x20) 
            b_ptr := add(mload(b),0x20)
        }

        a_ptr += a_len - b_len;
        for(uint i=0; i<b_len;i+=32){
            assembly{
                a_word := mload(add(a_ptr,i))
                b_word := mload(add(b_ptr,i))
            }

            if(a_word>b_word) return 1*trigger;
            if(b_word>a_word) return -1*trigger;
        }
        return 0; //same value.
    }

    /** @dev right_shift: right shift instance 'dividend' by 'value' bits.
      *           
      * parameter: instance a
      * parameter: instance b
      * parameter: bool signed
      * returns: int.
      */
    function right_shift(BigInt memory dividend, uint value) internal pure returns(BigInt memory){
        //TODO use memcpy for cheap rightshift where input is multiple of 8 (byte size)
        bytes memory result;
        uint word_shifted;
        uint mask_shift = 256-value;
        uint mask;
        uint result_ptr;
        uint max;
        uint length = dividend.val.length;

        assembly {
            max := sub(0,32)
            result_ptr := add(mload(dividend), length)   
        }

        for(uint i= length-32; i<max;i-=32){                 //for each word:
            assembly{
                word_shifted := mload(result_ptr)               //get next word
                switch eq(i,0)                               //if i==0:
                case 1 { mask := 0 }                         // handles msword: no mask needed.
                default { mask := mload(sub(result_ptr,0x20)) } // else get mask.
            }
            word_shifted >>= value;                            //right shift current by value
            mask <<= mask_shift;                               // left shift next significant word by mask_shift
            assembly{ mstore(result_ptr, or(word_shifted,mask)) } // store OR'd mask and shifted value in-place
            result_ptr-=32;                                       // point to next value.
        }

        assembly{
            //the following code removes any leading words containing all zeroes in the result.
            result_ptr := add(result_ptr,0x20)
            for { }  eq(mload(result_ptr), 0) { } {
               result_ptr := add(result_ptr, 0x20) //push up the start pointer for the result..
               length  := sub(length,0x20) //and subtract a word (32 bytes) from the result length.
            }
            
            result := sub(result_ptr,0x20)
            mstore(result, length) 
        }
        
        dividend.val = result;
        return dividend;
    }
}


