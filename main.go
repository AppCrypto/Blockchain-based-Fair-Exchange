// 使用方法替换gnark-tests-main/solidity/contract文件夹下的main.go函数
package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"os"
	"os/exec"
	"strconv"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark-tests/abe"
	"github.com/consensys/gnark-tests/bn128"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/plonk"
	plonk_bn254 "github.com/consensys/gnark/backend/plonk/bn254"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/test"
)

// 存储groth的结构体——————以结构体的形式放入json文件中（一个结构体对应一个poof和input）
type Groth16_output struct {
	G_proof []*big.Int
	G_input [1]*big.Int
}

// 存储plonk的结构体——————以结构体的形式放入json文件中（一个结构体对应一个poof和input）
type Plonk_output struct {
	P_proof string
	P_input [1]*big.Int
}

/*
// 定义电路的变量

type Circuit struct {
	// struct tags on a variable is optional
	// default uses variable name and secret visibility.
	X frontend.Variable `gnark:"x"`
	Y frontend.Variable `gnark:",public"`
}

// 定义电路
func (circuit *Circuit) Define(api frontend.API) error {

	x3 := api.Mul(circuit.X, circuit.X, circuit.X)
	api.AssertIsEqual(circuit.Y, api.Add(x3, circuit.X, 5))
	return nil
}
*/

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

var globalVariable string = "789798794465798431564"

func main() {
	//创建电路——————————————————————————————————————（替换电路）——————————————（替换处）
	var circuit Circuit
	//创建一个证明————————————————————————————————————（替换证明）—————————————（替换处）
	/*
		var assignment = Circuit{
			X: 3,
			Y: 35,
		}
	*/

	var assignment = Circuit{
		PreImage: Str2Byte(globalVariable),
		Hash:     mimcHash(Str2Byte(globalVariable)),
	}

	// 根据电路setup groth16
	rcls, pk, err := generateGroth16(circuit)
	if err != nil {
		log.Fatal("groth16 error:", err)
	}

	//生成证明并保留参数至json文件
	err = new_groth_proof(assignment, rcls, pk, "gorth16_output") //"groth_output"，json文件名——————（替换文件名）——————（替换处）
	if err != nil {
		log.Fatal("groth16 error:", err)
	}

	/*
		scs, p_pk, err := generatePlonk(circuit)
		if err != nil {
			log.Fatal("plonk error:", err)
		}

		//生成证明并保留参数至json文件
		err = new_plonk_proof(assignment, scs, p_pk, "plonk_output") //"plonk_output"，json文件名——————（替换文件名）——————（替换处）
		if err != nil {
			log.Fatal("plonk error:", err)
		}
	*/

	cmd := exec.Command("/usr/bin/python3", "./verify.py") //go calls python verify.py directly
	stdout, err := cmd.Output()
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(string(stdout))
	fmt.Println("Exchange done")

	maabe := abe.NewMAABE()
	maabe.Test()
	const n int = 10
	const times int64 = 100
	//t := 10
	attribs := [n][]string{}
	auths := [n]*abe.MAABEAuth{}
	keys := [n][]*abe.MAABEKey{}

	ks1 := []*abe.MAABEKey{} // ok

	for i := 0; i < n; i++ {
		authi := "auth" + strconv.Itoa(i)
		attribs[i] = []string{authi + ":at1"}
		// create three authorities, each with two attributes
		auths[i], _ = maabe.NewMAABEAuth("auth1", attribs[i])

	}

	// create a msp struct out of the boolean formula
	policyStr := ""
	for i := 0; i < n-1; i++ {
		authi := "auth" + strconv.Itoa(i)
		policyStr += authi + ":at1 AND "
	}
	policyStr += "auth" + strconv.Itoa(n-1) + ":at1"
	//fmt.Println(policyStr)
	//msp, err := abe.BooleanToMSP("auth1:at1 AND auth2:at1 AND auth3:at1 AND auth4:at1", false)

	// define the set of all public keys we use
	pks := []*abe.MAABEPubKey{}
	for i := 0; i < n; i++ {
		pks = append(pks, auths[i].PubKeys())
	}

	startts := time.Now().UnixNano() / 1e3
	var ct *abe.MAABECipher
	// encrypt the message with the decryption policy in msp
	_, symKey, _ := bn128.RandomGT(rand.Reader)
	//fmt.Println(symKey)
	msg := symKey
	msp, _ := abe.BooleanToMSP(policyStr, false)
	for i := 0; i < int(times); i++ {
		ct, _ = maabe.Encrypt2(symKey, msp, pks)
	}
	endts := time.Now().UnixNano() / 1e3
	fmt.Printf("%d nodes encrypt time cost: %v μs ct size:%v kB\n", n, (endts-startts)/times, len(ct.String())/1024)
	// choose a single user's Global ID
	gid := "gid1"

	startts = time.Now().UnixNano() / 1e3
	//var key []*abe.MAABEKey
	for i := 0; i < int(times); i++ {
		//var key []*abe.MAABEKey
		_, _ = auths[0].GenerateAttribKeys(gid, attribs[0])
	}
	endts = time.Now().UnixNano() / 1e3
	fmt.Printf("%d nodes keygen time cost: %v μs \n", n, 2*(endts-startts)/times) //*2 due to LW CP-ABE
	for i := 0; i < n; i++ {
		keys[i], _ = auths[i].GenerateAttribKeys(gid, attribs[i])
		ks1 = append(ks1, keys[i][0])
	}
	startts = time.Now().UnixNano() / 1e3
	var msg1 *bn128.GT
	for i := 0; i < int(times); i++ {
		msg1, _ = maabe.Decrypt2(ct, ks1)
	}
	endts = time.Now().UnixNano() / 1e3
	fmt.Printf("%d nodes decrypt time cost: %v μs\n", n, (endts-startts)/times)
	fmt.Println(msg.String() == msg1.String())
}

// 初始化函数：根据电路setup groth16
func generateGroth16(circuit Circuit) (r1cs1 constraint.ConstraintSystem, pk groth16.ProvingKey, err error) {

	r1cs1, err = frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		return nil, nil, err
	}
	//生成groth的pk和vk
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

// groth生成参数函数：产生groth的proof和input
func new_groth_proof(assignment Circuit, r1cs constraint.ConstraintSystem, pk groth16.ProvingKey, name string) error {

	//创建一个见证者
	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		return err
	}
	//生成证明
	proof, err := groth16.Prove(r1cs, pk, witness)
	if err != nil {
		return err
	}

	// 获取证明的字节序列
	const fpSize = 4 * 8
	var buf bytes.Buffer
	proof.WriteRawTo(&buf)
	proofBytes := buf.Bytes()
	mergedArray := make([]*big.Int, 8) //存储proof
	var input [1]*big.Int              // 定义数组input，用于存储公开的见证（witness）值
	mergedArray[0] = new(big.Int).SetBytes(proofBytes[fpSize*0 : fpSize*1])
	mergedArray[1] = new(big.Int).SetBytes(proofBytes[fpSize*1 : fpSize*2])
	mergedArray[2] = new(big.Int).SetBytes(proofBytes[fpSize*2 : fpSize*3])
	mergedArray[3] = new(big.Int).SetBytes(proofBytes[fpSize*3 : fpSize*4])
	mergedArray[4] = new(big.Int).SetBytes(proofBytes[fpSize*4 : fpSize*5])
	mergedArray[5] = new(big.Int).SetBytes(proofBytes[fpSize*5 : fpSize*6])
	mergedArray[6] = new(big.Int).SetBytes(proofBytes[fpSize*6 : fpSize*7])
	mergedArray[7] = new(big.Int).SetBytes(proofBytes[fpSize*7 : fpSize*8])
	//num, err := strconv.Atoi(mimcHash(Str2Byte("111111111111")))
	//input[0] = new(big.Int).SetUint64(num) // 设置公开见证的值为35，这通常对应于证明中需要验证的某个具体值（替换input参数）
	input[0], _ = new(big.Int).SetString(mimcHash(Str2Byte(globalVariable)), 10)
	//将参数写入结构体
	groth16_output := Groth16_output{
		G_proof: mergedArray,
		G_input: input,
	}

	// 将结构体序列化为JSON并写入文件
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

// 初始化函数：根据电路setup plonk
func generatePlonk(circuit Circuit) (scs1 constraint.ConstraintSystem, pk plonk.ProvingKey, err error) {

	scs1, err = frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &circuit)
	if err != nil {
		return nil, nil, err
	}

	srs, err := test.NewKZGSRS(scs1)
	if err != nil {
		return nil, nil, err
	}
	//生成plonk的pk和vk
	pk, vk, err := plonk.Setup(scs1, srs)
	if err != nil {
		return nil, nil, err
	}
	{

		f, err := os.Create("cubic.plonk.vk")
		if err != nil {
			return nil, nil, err
		}
		_, err = vk.WriteTo(f)
		if err != nil {
			return nil, nil, err
		}
	}
	{
		f, err := os.Create("cubic.plonk.pk")
		if err != nil {
			return nil, nil, err
		}
		_, err = pk.WriteTo(f)
		if err != nil {
			return nil, nil, err
		}
	}

	{
		f, err := os.Create("contract_plonk.sol")
		if err != nil {
			return nil, nil, err
		}
		err = vk.ExportSolidity(f)
		if err != nil {
			return nil, nil, err
		}
	}
	return scs1, pk, nil
}

// plonk生成参数函数：产生plonk的proof和input
func new_plonk_proof(assignment Circuit, scs1 constraint.ConstraintSystem, pk plonk.ProvingKey, name string) error {
	//创建一个见证人
	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		return err
	}
	//生成proof
	plonk_proof, err := plonk.Prove(scs1, pk, witness)
	if err != nil {
		return err
	}

	p := plonk_proof.(*plonk_bn254.Proof) //存储proof
	var publicInputs [1]*big.Int          //存储input

	serializedProof := p.MarshalSolidity()
	publicInputs[0] = new(big.Int).SetUint64(35)
	encodedString := base64.StdEncoding.EncodeToString(serializedProof)
	//将数据写入结构体
	plonk_output := Plonk_output{
		P_proof: encodedString,
		P_input: publicInputs,
	}
	//将结构体序列化为JSON并写入文件
	file, err := os.Create(name + ".json")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	encoder := json.NewEncoder(file)
	if err := encoder.Encode(plonk_output); err != nil {
		log.Fatal(err)
	}

	return nil
}
