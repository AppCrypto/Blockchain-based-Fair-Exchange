pragma solidity ^0.8.0;

contract Exchange {

    uint256 constant GROUP_ORDER   = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

    uint256 constant G1x  = 1;
    uint256 constant G1y  = 2;

    uint256 constant negG1x = 1;
    uint256 constant negG1y = 21888242871839275222246405745257275088696311157297823662689037894645226208581;

    uint256 constant H1x  = 15264291051155210722230395084766962011373976396997290700295946518477517838363;
    uint256 constant H1y  = 18062169012241050521396281509436922807270932827014386397365657617881670284318;

    uint256 constant negH1x  = 15264291051155210722230395084766962011373976396997290700295946518477517838363;
    uint256 constant negH1y  = 3826073859598224700850124235820352281425378330283437265323380276763555924265;

    uint256[2][] TTPs_pks;

    uint256[2][] DecryptedShare;
    //Store the decryption share uploaded by the tallier

    mapping(uint256 => uint256) public invMap;

    constructor() {
        for (uint256 i= GROUP_ORDER-30 ; i< GROUP_ORDER +31; i++)
        {
            invMap[i+1] = inv(i+1, GROUP_ORDER);
        }
    }


    struct Exchange_Data
    {
        uint256 buyer_fee; 
        address seller;   
        address buyer;
    
        uint256[]  c1;
        uint256[]  c2;
        //store c_j
        uint256[]  v1;
        uint256[]  v2;
        //store v_j

        uint256[2][] D_Proof;
        //store DLEQ proof
        bytes ciphertext;

        uint256  tasktime;
    }

    Exchange_Data public Exchange_Instance;

    function SellerUpload(uint256[] memory  _c1 , uint256[] memory _c2, uint256[] memory _v1, uint256[] memory _v2, uint256[2][] memory _D_Proof, bytes memory _ciphertext, address _seller)
    public
    {
        Exchange_Instance.c1 = _c1;
        Exchange_Instance.c2 = _c2;
        Exchange_Instance.v1 = _v1;
        Exchange_Instance.v2 = _v2;
        Exchange_Instance.D_Proof = _D_Proof;
        Exchange_Instance.ciphertext = _ciphertext;
        Exchange_Instance.seller = _seller;

    }


    mapping (address => Exchange_Data) public ExchangeTasks;

    function BuyerUpload(address buyer,uint256 buy_fee) public payable
    {
        require(msg.value==buy_fee);
        Exchange_Instance.buyer = buyer;
        Exchange_Instance.buyer_fee = buy_fee;
        Exchange_Instance.tasktime = block.timestamp;
    }
    

    function show(address buyer) public returns (bytes memory, uint256[2][] memory){
        return (Exchange_Instance.ciphertext,TTPs_pks);
    }
    
     // Upload voter public key function and save to Tallires_pk array
    function Set_TTPs_PKs(uint256[2][] memory pk) public {
        TTPs_pks = pk;
    }

    /// return the negation of p, i.e. p.add(p.negate()) should be zero.
	function G1neg(uint256 p) pure internal returns (uint r) {
		// The prime q in the base field F_q for G1
		uint256 q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
            r = (q - (p % q));
	}

    function bn128_add(uint256[4] memory input)
    public returns (uint256[2] memory result) {
        // computes P + Q
        // input: 4 values of 256 bit each
        //  *) x-coordinate of point P
        //  *) y-coordinate of point P
        //  *) x-coordinate of point Q
        //  *) y-coordinate of point Q

        bool success;
        assembly {
            // 0x06     id of precompiled bn256Add contract
            // 0        number of ether to transfer
            // 128      size of call parameters, i.e. 128 bytes total
            // 64       size of call return value, i.e. 64 bytes / 512 bit for a BN256 curve point
            success := call(not(0), 0x06, 0, input, 128, result, 64)
        }
        require(success, "elliptic curve addition failed");
    }

    function bn128_multiply(uint256[3] memory input)
    public returns (uint256[2] memory result) {
        // computes P*x
        // input: 3 values of 256 bit each
        //  *) x-coordinate of point P
        //  *) y-coordinate of point P
        //  *) scalar x

        bool success;
        assembly {
            // 0x07     id of precompiled bn256ScalarMul contract
            // 0        number of ether to transfer
            // 96       size of call parameters, i.e. 96 bytes total (256 bit for x, 256 bit for y, 256 bit for scalar)
            // 64       size of call return value, i.e. 64 bytes / 512 bit for a BN256 curve point
            success := call(not(0), 0x07, 0, input, 96, result, 64)
        }
        require(success, "elliptic curve multiplication failed");
    }

     // Invert function, invert in group
    function inv(uint256 a, uint256 prime) public returns (uint256){
    	return modPow(a, prime-2, prime);
    }

    function modPow(uint256 base, uint256 exponent, uint256 modulus) internal returns (uint256) {
	    uint256[6] memory input = [32,32,32,base,exponent,modulus];
	    uint256[1] memory result;
	    assembly {
	      if iszero(call(not(0), 0x05, 0, input, 0xc0, result, 0x20)) {
	        revert(0, 0)
	      }
	    }
	    return result[0];
	}

    function DLEQ_verify(
        uint256[2] memory x1, uint256[2] memory y1,
        uint256[2] memory x2, uint256[2] memory y2,
        uint256[2] memory proof
    )
    public returns (bool proof_is_valid)
    {
        uint256[2] memory tmp1;
        uint256[2] memory tmp2;

        tmp1 = bn128_multiply([x1[0], x1[1], proof[1]]);
        tmp2 = bn128_multiply([y1[0], y1[1], proof[0]]);
        uint256[2] memory a1 = bn128_add([tmp1[0], tmp1[1], tmp2[0], tmp2[1]]);

        tmp1 = bn128_multiply([x2[0], x2[1], proof[1]]);
        tmp2 = bn128_multiply([y2[0], y2[1], proof[0]]);
        uint256[2] memory a2 = bn128_add([tmp1[0], tmp1[1], tmp2[0], tmp2[1]]);

        uint256 challenge = uint256(keccak256(abi.encodePacked(a1, a2, x1, y1, x2, y2)));
        proof_is_valid = challenge == proof[0];
    }

      //RScode verify on-chain
    function RScode_verify() public returns(bool)
    {
        uint256[2] memory sum;
        sum[0] = H1x;
        sum[1] = H1y;
        uint256[2] memory codeword;
        uint len = Exchange_Instance.v1.length+1;
        uint i = 1;
        uint j = 1;
        uint256 result=1;
        for(i=1;i< len;i++)
        {
            result = 1;
            for(j=1; j< len;j++)
            {
                if(i!=j)
                {
                    result=mulmod(result, invMap[i+GROUP_ORDER-j], GROUP_ORDER);
                }
            }
            codeword = bn128_multiply([Exchange_Instance.v1[i-1], Exchange_Instance.v2[i-1],result]);
            sum=bn128_add([sum[0],sum[1],codeword[0],codeword[1]]);
        }
        if(sum[0]==H1x && sum[1]== H1y)
        {
            return true;
        }
        else
        {
            return false;
        }
    }

     // on-chain PVSS.DVerify function
    function PVSS_Verify() public returns(bool)
    {

        uint elements = Exchange_Instance.c1.length;  //get array length
        for (uint i = 0; i < elements; i++)
        {

            if(!DLEQ_verify([H1x,H1y],[Exchange_Instance.v1[i], Exchange_Instance.v2[i]],[TTPs_pks[i][0],TTPs_pks[i][1]],[Exchange_Instance.c1[i], Exchange_Instance.c2[i]],[Exchange_Instance.D_Proof[i][0],Exchange_Instance.D_Proof[i][1]]))
            {
                return false;
            }
        }

        return RScode_verify();
        //return true;
    }

        // on-chain PVSS.PVerify function
    function PVSS_PVerify(uint256[2] memory pk, uint256[2] memory sh_i, uint256[2] memory c_i, uint256[2] memory Proof ) public returns(bool)
    {
        if(!DLEQ_verify([G1x,G1y],[pk[0], pk[1]],[sh_i[0],sh_i[1]],[c_i[0], c_i[1]],[Proof[0],Proof[1]]))
        {
            return false;
        }

        return true;
    }

    function Decrypted_ShareUpload(uint No, uint256[2] memory DShare, uint256[2] memory P_Proof) public returns (bool)
    {
        uint256[2] memory ShareC;
        ShareC[0] = Exchange_Instance.c1[No - 1];
        ShareC[1] = Exchange_Instance.c2[No - 1];
        if(PVSS_PVerify(TTPs_pks[No-1], DShare, ShareC, P_Proof))
        {
            //DecryptedShare.push(DShare);
            return true;
        }
        return false;
    }

    function show2() public returns (uint256[2][] memory)
    {
        return DecryptedShare;
    }

    function DownloadCiphertext() public returns (bytes memory){
        return Exchange_Instance.ciphertext;
    }
    
    
    function ETHtransfer(address seller) public
    {
        require( seller == Exchange_Instance.seller );
        address payable recipient = payable(seller);
        uint256 amount=(Exchange_Instance.buyer_fee);
        recipient.transfer(amount);
    }
    
    function DownloadShare(uint No) public view returns (uint256[2] memory) {
        uint256[2] memory ShareC;
        ShareC[0] = Exchange_Instance.c1[No - 1];
        ShareC[1] = Exchange_Instance.c2[No - 1];
        return ShareC;
    }

     // Find the Lagrange interpolation coefficients
    function lagrangeCoefficient(uint256 t) public returns (uint256[] memory){

        uint256[] memory lar2 = new uint256[](t);
        uint256 result = 1;
        uint256 inverse = 0;
        uint256 intermediate_result = 0;
        uint i =1;
        uint j =1;
        for ( i = 1; i< t+1 ; i++)
        {
            result=1;
            for (j = 1; j < t+1;j++) {
                if (i != j) {
                    inverse = invMap[j+GROUP_ORDER-i];
                    intermediate_result = mulmod(j,inverse,GROUP_ORDER);
                    result = mulmod(result,intermediate_result,GROUP_ORDER);
                }
            }
            lar2[i-1]=result;
        }
        return lar2;
    }

        // on-chain interpolation function
    function  Interpolate(
        uint256[2][] memory V, uint256[] memory lagrange_coefficient
    )
    public returns (uint256[2] memory)
    {
        uint256[2] memory a1;
        uint256[2] memory temp;
        a1[0] = 0;
        a1[1] = 0;
        uint elements=lagrange_coefficient.length;
        //to get the array length
        for(uint i=0;i<elements;i++)
        {
            temp = bn128_multiply([V[i][0], V[i][1],lagrange_coefficient[i]]);
            a1 = bn128_add([a1[0], a1[1], temp[0], temp[1]]);
        }
        return a1;
    }

     // on-chain tally function, no needs any off-chain input for arguments
    function Reconstruction()
    public returns(uint256[2] memory)
    {
        uint256[] memory lagrange_coefficient;
        lagrange_coefficient = lagrangeCoefficient(DecryptedShare.length);
        uint256[2] memory G1ACC;
        G1ACC =  Interpolate(DecryptedShare, lagrange_coefficient);
        return G1ACC;
        //return lagrange_coefficient;
    }
}