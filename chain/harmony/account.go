package harmony

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/harmony-one/harmony/core/types"
	common2 "github.com/harmony-one/harmony/rpc/common"
	"github.com/renproject/multichain/api/account"
	"github.com/renproject/multichain/api/address"
	"github.com/renproject/multichain/api/contract"
	"github.com/renproject/pack"
	"math/big"
)

const (
	DefaultShardID = 1
	DefaultHost    = "https://rpc.s0.t.hmny.io"
)

type TxBuilderOptions struct {
	ChainID *big.Int
}

type TxBuilder struct {
	client  *Client
	chainID *big.Int
}

func NewTxBuilder(options TxBuilderOptions, client *Client) account.TxBuilder {
	return TxBuilder{
		client:  client,
		chainID: options.ChainID,
	}
}

func (txBuilder TxBuilder) BuildTx(ctx context.Context, from, to address.Address, value, nonce, gasLimit, gasPrice, gasCap pack.U256, payload pack.Bytes) (account.Tx, error) {
	chainId, err := txBuilder.client.ChainId(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch Chain ID: %v", err)
	}
	tx := types.NewTransaction(
		nonce.Int().Uint64(),
		common.HexToAddress(string(to)),
		DefaultShardID,
		value.Int(),
		gasLimit.Int().Uint64(),
		gasPrice.Int(),
		payload)
	return Tx{
		harmonyTx: *tx,
		chainId:   chainId,
		signed:    false,
	}, nil
}

type Tx struct {
	harmonyTx types.Transaction
	chainId   *big.Int
	signed    bool
}

func (tx Tx) Hash() pack.Bytes {
	return pack.NewBytes(tx.harmonyTx.Hash().Bytes())
}

func (tx Tx) From() address.Address {
	from, err := tx.harmonyTx.SenderAddress()
	if err == nil {
		return address.Address(from.String())
	}
	return ""
}

func (tx Tx) To() address.Address {
	to := tx.harmonyTx.To()
	if to != nil {
		return address.Address(to.String())
	}
	return ""
}

func (tx Tx) Value() pack.U256 {
	return pack.NewU256FromInt(tx.harmonyTx.Value())
}

func (tx Tx) Nonce() pack.U256 {
	return pack.NewU256FromU64(pack.NewU64(tx.harmonyTx.Nonce()))
}

func (tx Tx) Payload() contract.CallData {
	return tx.harmonyTx.Data()
}

func (tx Tx) Sighashes() ([]pack.Bytes32, error) {
	const digestLength = 32
	var (
		digestHash [32]byte
		sighashes  []pack.Bytes32
	)
	h := types.NewEIP155Signer(tx.chainId).Hash(&tx.harmonyTx).Bytes()
	if len(h) != digestLength {
		return nil, fmt.Errorf("hash is required to be exactly %d bytes (%d)", digestLength, len(h))
	}
	copy(digestHash[:], h[:32])
	sighashes = append(sighashes, digestHash)
	return sighashes, nil
}

func (tx Tx) Sign(signatures []pack.Bytes65, pubKey pack.Bytes) error {
	if len(signatures) != 1 {
		return fmt.Errorf("expected 1 signature, got %v signatures", len(signatures))
	}
	signedTx, err := tx.harmonyTx.WithSignature(types.NewEIP155Signer(tx.chainId), signatures[0].Bytes())
	if err != nil {
		return err
	}
	tx.harmonyTx = *signedTx
	tx.signed = true
	return nil
}

func (tx Tx) Serialize() (pack.Bytes, error) {
	serializedTx, err := rlp.EncodeToBytes(tx.harmonyTx)
	if err != nil {
		return pack.Bytes{}, err
	}
	return pack.NewBytes(serializedTx), nil
}

type ClientOptions struct {
	Host string
}

type Client struct {
	opts ClientOptions
}

func (opts ClientOptions) WithHost(host string) ClientOptions {
	opts.Host = host
	return opts
}

func (opts ClientOptions) WithDefaultHost() ClientOptions {
	opts.Host = DefaultHost
	return opts
}

func (c Client) LatestBlock(context.Context) (pack.U64, error) {
	const method = "hmyv2_blockNumber"
	response, err := SendData(method, []byte{}, c.opts.Host)
	if err != nil {
		fmt.Println(err)
		return pack.NewU64(0), err
	}
	var latestBlock pack.U64
	if err := json.Unmarshal(*response.Result, &latestBlock); err != nil {
		return pack.NewU64(0), fmt.Errorf("decoding result: %v", err)
	}
	return latestBlock, nil
}

func (c Client) AccountBalance(ctx context.Context, addr address.Address) (pack.U256, error) {
	accAddress := common.HexToAddress(string(addr))
	data := []byte(fmt.Sprintf("[\"%s\"]", accAddress))
	const method = "hmyv2_getBalance"
	response, err := SendData(method, data, c.opts.Host)
	if err != nil {
		fmt.Println(err)
		return pack.U256{}, err
	}
	var balance pack.U256
	if err := json.Unmarshal(*response.Result, &balance); err != nil {
		return pack.U256{}, fmt.Errorf("decoding result: %v", err)
	}
	return balance, nil
}

func (c Client) AccountNonce(ctx context.Context, addr address.Address) (pack.U256, error) {
	accAddress := common.HexToAddress(string(addr))
	data := []byte(fmt.Sprintf("[\"%s\", \"%s\"]", accAddress, "SENT"))
	const method = "hmyv2_getTransactionsCount"
	response, err := SendData(method, data, c.opts.Host)
	if err != nil {
		fmt.Println(err)
		return pack.U256{}, err
	}
	var nonce pack.U256
	if err := json.Unmarshal(*response.Result, &nonce); err != nil {
		return pack.U256{}, fmt.Errorf("decoding result: %v", err)
	}
	return nonce, nil
}

func (c Client) Tx(ctx context.Context, hash pack.Bytes) (account.Tx, pack.U64, error) {
	data := []byte(fmt.Sprintf("[\"%s\"]", string(hash)))
	const method = "hmyv2_getTransactionByHash"
	response, err := SendData(method, data, c.opts.Host)
	if err != nil {
		fmt.Println(err)
		return nil, pack.NewU64(0), err
	}
	var harmonyTx types.Transaction
	if err := json.Unmarshal(*response.Result, &harmonyTx); err != nil {
		return nil, pack.NewU64(0), fmt.Errorf("decoding result: %v", err)
	}
	tx := Tx{
		harmonyTx: harmonyTx,
	}
	return &tx, pack.NewU64(0), nil
}

func (c Client) SubmitTx(ctx context.Context, tx account.Tx) error {
	data := []byte(fmt.Sprintf("[\"%s\"]", string(tx.Hash())))
	const method = "hmyv2_sendRawTransaction"
	response, err := SendData(method, data, c.opts.Host)
	if err != nil {
		fmt.Println(err)
		return err
	}
	var nonce pack.U256
	if err := json.Unmarshal(*response.Result, &nonce); err != nil {
		return fmt.Errorf("decoding result: %v", err)
	}
	return nil
}

func (c Client) ChainId(ctx context.Context) (*big.Int, error) {
	const method = "hmyv2_getNodeMetadata"
	response, err := SendData(method, []byte{}, c.opts.Host)
	if err != nil {
		fmt.Println(err)
		return big.NewInt(0), err
	}
	var nodeMetadata common2.NodeMetadata
	if err := json.Unmarshal(*response.Result, &nodeMetadata); err != nil {
		return big.NewInt(0), fmt.Errorf("decoding result: %v", err)
	}
	return nodeMetadata.ChainConfig.ChainID, nil
}
