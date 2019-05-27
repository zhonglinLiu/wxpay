package wxpay

const (
	Fail                       = "FAIL"
	Success                    = "SUCCESS"
	HMACSHA256                 = "HMAC-SHA256"
	MD5                        = "MD5"
	Sign                       = "sign"
	MicroPayUrl                = "https://api.mch.weixin.qq.com/pay/micropay"
	UnifiedOrderUrl            = "https://api.mch.weixin.qq.com/pay/unifiedorder"
	OrderQueryUrl              = "https://api.mch.weixin.qq.com/pay/orderquery"
	ReverseUrl                 = "https://api.mch.weixin.qq.com/secapi/pay/reverse"
	CloseOrderUrl              = "https://api.mch.weixin.qq.com/pay/closeorder"
	RefundUrl                  = "https://api.mch.weixin.qq.com/secapi/pay/refund"
	RefundQueryUrl             = "https://api.mch.weixin.qq.com/pay/refundquery"
	DownloadBillUrl            = "https://api.mch.weixin.qq.com/pay/downloadbill"
	DownloadFundFlowUrl        = "https://api.mch.weixin.qq.com/pay/downloadfundflow"
	ReportUrl                  = "https://api.mch.weixin.qq.com/payitil/report"
	ShortUrl                   = "https://api.mch.weixin.qq.com/tools/shorturl"
	AuthCodeToOpenidUrl        = "https://api.mch.weixin.qq.com/tools/authcodetoopenid"
	SandboxMicroPayUrl         = "https://api.mch.weixin.qq.com/sandboxnew/pay/micropay"
	SandboxUnifiedOrderUrl     = "https://api.mch.weixin.qq.com/sandboxnew/pay/unifiedorder"
	SandboxOrderQueryUrl       = "https://api.mch.weixin.qq.com/sandboxnew/pay/orderquery"
	SandboxReverseUrl          = "https://api.mch.weixin.qq.com/sandboxnew/secapi/pay/reverse"
	SandboxCloseOrderUrl       = "https://api.mch.weixin.qq.com/sandboxnew/pay/closeorder"
	SandboxRefundUrl           = "https://api.mch.weixin.qq.com/sandboxnew/secapi/pay/refund"
	SandboxRefundQueryUrl      = "https://api.mch.weixin.qq.com/sandboxnew/pay/refundquery"
	SandboxDownloadBillUrl     = "https://api.mch.weixin.qq.com/sandboxnew/pay/downloadbill"
	SandboxDownloadFundFlowUrl = "https://api.mch.weixin.qq.com/sandboxnew/pay/downloadfundflow"
	SandboxReportUrl           = "https://api.mch.weixin.qq.com/sandboxnew/payitil/report"
	SandboxShortUrl            = "https://api.mch.weixin.qq.com/sandboxnew/tools/shorturl"
	SandboxAuthCodeToOpenidUrl = "https://api.mch.weixin.qq.com/sandboxnew/tools/authcodetoopenid"
	FraudUrl 				   = "https://fraud.mch.weixin.qq.com/risk/getpublickey"
	SandboxFraudUrl			   = "https://fraud.mch.weixin.qq.com/sandboxnew/risk/getpublickey"
	PayToBank				   = "https://api.mch.weixin.qq.com/mmpaysptrans/pay_bank"
	SandboxPayToBank 		   = "https://api.mch.weixin.qq.com/sandboxnew/mmpaysptrans/pay_bank"
	PromotionTransfersUrl 	   = "https://api.mch.weixin.qq.com/mmpaymkttransfers/promotion/transfers"
	SandboxPromotionTransfersUrl = "https://api.mch.weixin.qq.com/sandboxnew/mmpaymkttransfers/promotion/transfers"
)
