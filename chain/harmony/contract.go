package harmony

import (
	"context"
	"fmt"
	"github.com/renproject/multichain/api/address"
	"github.com/renproject/multichain/api/contract"
	"github.com/renproject/pack"
)

func (c Client) CallContract(ctx context.Context, addr address.Address, callData contract.CallData) (pack.Bytes, error) {
	const method = "hmyv2_call"
	data := []byte(fmt.Sprintf("[{\"to\": \"%s\", \"data\": \"%s\"}]", string(addr), string(callData)))
	response, err := SendData(method, data, c.opts.Host)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	return pack.NewBytes(*response.Result), nil
}
