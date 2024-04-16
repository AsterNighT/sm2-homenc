package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"

	"math/big"

	"github.com/xlcetc/cryptogm/sm/sm2"
)

var sk *sm2.PrivateKey
var pk *sm2.PublicKey

type BigInt struct {
	big.Int
}

func (i BigInt) MarshalJSON() ([]byte, error) {
	return []byte(i.String()), nil
}

func (i *BigInt) UnmarshalJSON(p []byte) error {
	if string(p) == "null" {
		return nil
	}
	var z big.Int
	_, ok := z.SetString(string(p), 10)
	if !ok {
		return fmt.Errorf("not a valid big integer: %s", p)
	}
	i.Int = z
	return nil
}

func testsm2hadd(m1 *big.Int, m2 *big.Int) {
	sk, _ := sm2.GenerateKey(rand.Reader)
	pk := sk.PublicKey
	//fmt.Println(messages[0].String())
	//test encryption

	c1x, c1y, c2x, c2y := sm2.LgwHEnc(rand.Reader, &pk, m1)
	c1x2, c1y2, c2x2, c2y2 := sm2.LgwHEnc(rand.Reader, &pk, m2)
	cr1x, cr1y := pk.Curve.Add(c1x, c1y, c1x2, c1y2)
	cr2x, cr2y := pk.Curve.Add(c2x, c2y, c2x2, c2y2)
	result, _ := sm2.LgwHDec(sk, cr1x, cr1y, cr2x, cr2y)
	fmt.Println(result)
}

type AddBody struct {
	Lhs [4]BigInt `json:"lhs"`
	Rhs [4]BigInt `json:"rhs"`
}
type AddResponse struct {
	Lhs [4]BigInt `json:"lhs"`
}

type addHandler struct{}

func (h *addHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var addBody AddBody
	err := json.NewDecoder(r.Body).Decode(&addBody)
	if err != nil {
		w.WriteHeader(400)
		w.Write([]byte(err.Error()))
		return
	}
	r1x, r1y := pk.Curve.Add(&addBody.Lhs[0].Int, &addBody.Lhs[1].Int, &addBody.Rhs[0].Int, &addBody.Rhs[1].Int)
	r2x, r2y := pk.Curve.Add(&addBody.Lhs[2].Int, &addBody.Lhs[3].Int, &addBody.Rhs[2].Int, &addBody.Rhs[3].Int)
	addResponse := AddResponse{
		Lhs: [4]BigInt{{*r1x}, {*r1y}, {*r2x}, {*r2y}},
	}
	bytes, _ := json.Marshal(addResponse)
	// fmt.Printf("Writing %v to response", bytes)
	w.Write(bytes)
}

type DecBody struct {
	Lhs [4]BigInt `json:"lhs"`
}
type DecResponse struct {
	Data int `json:"data"`
}

type decHandler struct{}

func (h *decHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var decBody DecBody
	err := json.NewDecoder(r.Body).Decode(&decBody)
	if err != nil {
		w.WriteHeader(400)
		w.Write([]byte(err.Error()))
		return
	}
	// bytes_dec, _ := json.Marshal(decBody)
	// fmt.Printf("Decrypting %v", bytes_dec)
	data, err := sm2.LgwHDec(sk, &decBody.Lhs[0].Int, &decBody.Lhs[1].Int, &decBody.Lhs[2].Int, &decBody.Lhs[3].Int)
	if err != nil {
		w.WriteHeader(400)
		w.Write([]byte(err.Error()))
		return
	}
	decResponse := DecResponse{
		data,
	}
	bytes, _ := json.Marshal(decResponse)
	// fmt.Printf("Writing %v to response", bytes)
	w.Write(bytes)
}

type EncBody struct {
	Data int `json:"data"`
}

type EncResponse struct {
	Lhs [4]BigInt `json:"lhs"`
}

type encHandler struct{}

func (h *encHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var encBody EncBody
	err := json.NewDecoder(r.Body).Decode(&encBody)
	if err != nil {
		w.WriteHeader(400)
		w.Write([]byte(err.Error()))
		return
	}
	// fmt.Printf("Receiving %v\n", encBody.Data)
	bitint := big.NewInt(int64(encBody.Data))
	r1x, r1y, r2x, r2y := sm2.LgwHEnc(rand.Reader, pk, bitint)
	encResponse := EncResponse{
		Lhs: [4]BigInt{{*r1x}, {*r1y}, {*r2x}, {*r2y}},
	}
	bytes, err := json.Marshal(encResponse)
	if err != nil {
		w.WriteHeader(400)
		w.Write([]byte(err.Error()))
		return
	}
	// fmt.Printf("Writing %v to response", bytes)
	w.Write(bytes)
}

const port uint = 8080

func main() {
	fmt.Println("Initialized")
	sk, _ = sm2.GenerateKey(rand.Reader)
	pk = &sk.PublicKey

	mux := http.NewServeMux()
	mux.Handle("/add", &addHandler{})
	mux.Handle("/add/", &addHandler{})
	mux.Handle("/enc", &encHandler{})
	mux.Handle("/enc/", &encHandler{})
	mux.Handle("/dec", &decHandler{})
	mux.Handle("/dec/", &decHandler{})
	addr := fmt.Sprintf(":%d", port)
	fmt.Printf("Listening at %s\n", addr)
	http.ListenAndServe(addr, mux)

	// data := 12335
	// bitint := big.NewInt(int64(data))
	// r1x, r1y, r2x, r2y := sm2.LgwHEnc(rand.Reader, pk, bitint)
	// addResponse := AddResponse{
	// 	Lhs: [4]BigInt{{*r1x}, {*r1y}, {*r2x}, {*r2y}},
	// }
	// bytes, _ := json.Marshal(addResponse)
	// var decBody DecBody
	// _ = json.Unmarshal(bytes, &decBody)
	// dec_data, _ := sm2.LgwHDec(sk, &decBody.Lhs[0].Int, &decBody.Lhs[1].Int, &decBody.Lhs[2].Int, &decBody.Lhs[3].Int)
	// fmt.Println(data, dec_data)
}
