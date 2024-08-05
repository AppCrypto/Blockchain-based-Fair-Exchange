
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	"github.com/consensys/gnark/std/hash/mimc"
)

// The struct —————— that stores groth is put into the json file as a struct (one poof and one input)
type Groth16_output struct {
	G_proof []*big.Int
	G_input [1]*big.Int
}


// Defining the circuit

type Circuit struct {
	PreImage frontend.Variable
	Hash     frontend.Variable `gnark:",public"`
}

func (circuit *Circuit) Define(api frontend.API) error {
	api.Println(circuit.Hash)
	api.Println(circuit.PreImage)
	mimc, _ := mimc.NewMiMC(api)
	mimc.Write(circuit.PreImage)
	api.Println(mimc.Sum())
	api.AssertIsEqual(circuit.Hash, mimc.Sum())
	return nil
}

func mimcHash(data []byte) string {
	f := bn254.NewMiMC()
	//f.Reset()
	f.Write(data)
	hash := f.Sum(nil)
	hashInt := big.NewInt(0).SetBytes(hash)
	return hashInt.String()
}

func Str2Byte(v string) []byte {
	var f fr.Element
	f.SetString(v)
	b := f.Bytes()
	return b[:]
}

var Alice_Hash string = "789798794465798431564"

var Bob_Hash string = "7897987944688885798431564"

func main() {
	//fmt.Println("......................................... zkSNARKs Verify begin .................................................")

	//Creating circuits
	var circuit Circuit

	//Creating a proof
	var assignment1 = Circuit{
		PreImage: Str2Byte(Alice_Hash),
		Hash:     mimcHash(Str2Byte(Alice_Hash)),
	}

	fileContent, err := ioutil.ReadFile("zkSNARKs_Hash.txt")
	if err != nil {
		fmt.Println("An error occurred while reading the file:", err)
		return
	}

	// Converts the byte slice to a string
	Alice_Hash = string(fileContent)
	//fmt.Println(Alice_Hash)

	re := regexp.MustCompile("[0-9]+")               
	tempstring11 := re.FindAllString(Alice_Hash, -1) 
	Alice_Hash = strings.Join(tempstring11, "")
	//fmt.Println(Alice_Hash)
	assignment1.PreImage = Str2Byte(Alice_Hash)
	assignment1.Hash = mimcHash(Str2Byte(Alice_Hash))

	// According to the circuit setup groth16
	rcls, pk, err := generateGroth16(circuit)
	if err != nil {
		log.Fatal("groth16 error:", err)
	}

	//Generate proof and save parameters to json file
	err = new_groth_proof1(assignment1, rcls, pk, "gorth16_output") //"groth_output"，json
	if err != nil {
		log.Fatal("groth16 error:", err)
	}
	//fmt.Println(Alice_grothVerify())
	fmt.Println("zkSNARKs verify resunlt:", Alice_grothVerify())
}

// Initialization function: According to the circuit setup groth16
func generateGroth16(circuit Circuit) (r1cs1 constraint.ConstraintSystem, pk groth16.ProvingKey, err error) {

	r1cs1, err = frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		return nil, nil, err
	}
	//Generate pk and vk for groth
	pk, vk, err := groth16.Setup(r1cs1)
	if err != nil {
		return nil, nil, err
	}
	{
		f, err := os.Create("cubic.g16.vk")
		if err != nil {
			return nil, nil, err
		}
		_, err = vk.WriteRawTo(f)
		if err != nil {
			return nil, nil, err
		}
	}
	{
		f, err := os.Create("cubic.g16.pk")
		if err != nil {
			return nil, nil, err
		}
		_, err = pk.WriteRawTo(f)
		if err != nil {
			return nil, nil, err
		}
	}

	{
		f, err := os.Create("contract_g16.sol")
		if err != nil {
			return nil, nil, err
		}
		err = vk.ExportSolidity(f)
		if err != nil {
			return nil, nil, err
		}
	}
	return r1cs1, pk, nil
}

// groth generation argument function: produces proof and input of groth
func new_groth_proof1(assignment Circuit, r1cs constraint.ConstraintSystem, pk groth16.ProvingKey, name string) error {

	//creating a witness
	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		return err
	}
	//creating a proof
	proof, err := groth16.Prove(r1cs, pk, witness)
	if err != nil {
		return err
	}

	// Get the byte sequence of the proof
	const fpSize = 4 * 8
	var buf bytes.Buffer
	proof.WriteRawTo(&buf)
	proofBytes := buf.Bytes()
	mergedArray := make([]*big.Int, 8) //Storing proof
	var input [1]*big.Int              // Define the input array to store the public witness value
	mergedArray[0] = new(big.Int).SetBytes(proofBytes[fpSize*0 : fpSize*1])
	mergedArray[1] = new(big.Int).SetBytes(proofBytes[fpSize*1 : fpSize*2])
	mergedArray[2] = new(big.Int).SetBytes(proofBytes[fpSize*2 : fpSize*3])
	mergedArray[3] = new(big.Int).SetBytes(proofBytes[fpSize*3 : fpSize*4])
	mergedArray[4] = new(big.Int).SetBytes(proofBytes[fpSize*4 : fpSize*5])
	mergedArray[5] = new(big.Int).SetBytes(proofBytes[fpSize*5 : fpSize*6])
	mergedArray[6] = new(big.Int).SetBytes(proofBytes[fpSize*6 : fpSize*7])
	mergedArray[7] = new(big.Int).SetBytes(proofBytes[fpSize*7 : fpSize*8])

	//input[0] = new(big.Int).SetUint64(35) 
        // Set the value of the public witness to 35, which usually corresponds to some specific value to be verified in the proof (replace the input argument).
	input[0], _ = new(big.Int).SetString(mimcHash(Str2Byte(Alice_Hash)), 10)
	
	groth16_output := Groth16_output{
		G_proof: mergedArray,
		G_input: input,
	}

	// Serialize the struct to JSON and write it to a file
	file, err := os.Create(name + ".json")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	encoder := json.NewEncoder(file)
	if err := encoder.Encode(groth16_output); err != nil {
		log.Fatal(err)
	}
	return nil
}

func Alice_grothVerify() bool {
	cmd := exec.Command("/usr/bin/python3", "./utils/verify.py") //go calls python verify.py directly
	stdout, _ := cmd.Output()
	output := strings.TrimSpace(string(stdout))
	if output == "True" {
		return true
	} else {
		return false
	}
}

/*
func Bob_grothVerify() bool {
	cmd := exec.Command("/usr/bin/python3", "./verify_Bob.py") //go calls python verify.py directly
	stdout, _ := cmd.Output()
	output := strings.TrimSpace(string(stdout))
	if output == "True" {
		return true
	} else {
		return false
	}
}
*/
