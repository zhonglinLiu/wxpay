package wxpay
import (
	"errors"
)

// 处理 HTTPS API返回数据，转换成Map对象。return_code为SUCCESS时，不验证签名。
func (c *Client) processResponseXmlNotSign(xmlStr string) (Params, error) {
	var returnCode string
	params := XmlToMap(xmlStr)
	if params.ContainsKey("return_code") {
		returnCode = params.GetString("return_code")
	} else {
		return nil, errors.New("no return_code in XML")
	}
	if returnCode == Fail {
		return params, nil
	} else if returnCode == Success {
		return params, nil
	} else {
		return nil, errors.New("return_code value is invalid in XML")
	}
}

// 调用获取RSA公钥API获取RSA公钥
func (c *Client) Fraud(params Params) (Params, error) {
	var url string
	if c.account.isSandbox {
		url = SandboxFraudUrl
	} else {
		url = FraudUrl
	}
	xmlStr, err := c.postWithCert(url, params)
	if err != nil {
		return nil, err
	}
	return c.processResponseXmlNotSign(xmlStr)
}

// 企业向微信用户个人付款
func (c *Client) PromotionTransfers(params Params) (Params, error) {
	var url string
	if c.account.isSandbox {
		url = SandboxPromotionTransfersUrl
	} else {
		url = PromotionTransfersUrl
	}
	xmlStr, err := c.postWithCertNotFill(url, params)
	if err != nil {
		return nil, err
	}
	return c.processResponseXmlNotSign(xmlStr)
}

// 企业付款到银行卡API  待测试
func (c *Client) PayToBank(params Params) (Params, error) {
	var url string
	if c.account.isSandbox {
		url = SandboxPayToBank
	} else {
		url = PayToBank
	}
	xmlStr, err := c.postWithCert(url, params)
	if err != nil {
		return nil, err
	}
	return c.processResponseXml(xmlStr)
}