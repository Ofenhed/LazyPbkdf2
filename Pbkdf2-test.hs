import Data.ByteString.Lazy.Char8 as C8
import Pbkdf2 (hmacSha512Pbkdf2)
import Data.Binary as B
import Data.ByteString.Base16.Lazy as B16
import Data.Int (Int64)
import System.IO (hSetBuffering, stdout, BufferMode (NoBuffering) )
import System.Exit (exitFailure, exitSuccess)

-- Inofficial test suite fetched from http://stackoverflow.com/a/19898265
test_vectors :: [(ByteString, ByteString, Integer, Int64, ByteString)]
test_vectors = [(C8.pack "passDATAb00AB7YxDTT", C8.pack "saltKEYbcTcXHCBxtjD", 1, 64, C8.pack "CBE6088AD4359AF42E603C2A33760EF9D4017A7B2AAD10AF46F992C660A0B461ECB0DC2A79C2570941BEA6A08D15D6887E79F32B132E1C134E9525EEDDD744FA"), 
  (C8.pack "passDATAb00AB7YxDTT", C8.pack "saltKEYbcTcXHCBxtjD", 100000, 64, C8.pack "ACCDCD8798AE5CD85804739015EF2A11E32591B7B7D16F76819B30B0D49D80E1ABEA6C9822B80A1FDFE421E26F5603ECA8A47A64C9A004FB5AF8229F762FF41F"), 
  (C8.pack "passDATAb00AB7YxDTTl", C8.pack "saltKEYbcTcXHCBxtjD2", 1, 64, C8.pack "8E5074A9513C1F1512C9B1DF1D8BFFA9D8B4EF9105DFC16681222839560FB63264BED6AABF761F180E912A66E0B53D65EC88F6A1519E14804EBA6DC9DF137007"), 
  (C8.pack "passDATAb00AB7YxDTTl", C8.pack "saltKEYbcTcXHCBxtjD2", 100000, 64, C8.pack "594256B0BD4D6C9F21A87F7BA5772A791A10E6110694F44365CD94670E57F1AECD797EF1D1001938719044C7F018026697845EB9AD97D97DE36AB8786AAB5096"), 
  (C8.pack "passDATAb00AB7YxDTTlR", C8.pack "saltKEYbcTcXHCBxtjD2P", 1, 64, C8.pack "A6AC8C048A7DFD7B838DA88F22C3FAB5BFF15D7CB8D83A62C6721A8FAF6903EAB6152CB7421026E36F2FFEF661EB4384DC276495C71B5CAB72E1C1A38712E56B"), 
  (C8.pack "passDATAb00AB7YxDTTlR", C8.pack "saltKEYbcTcXHCBxtjD2P", 100000, 64, C8.pack "94FFC2B1A390B7B8A9E6A44922C330DB2B193ADCF082EECD06057197F35931A9D0EC0EE5C660744B50B61F23119B847E658D179A914807F4B8AB8EB9505AF065"), 
  (C8.pack "passDATAb00AB7YxDTTlRH2dqxDx19GDxDV1zFMz7E6QVqKIzwOtMnlxQLttpE5", C8.pack "saltKEYbcTcXHCBxtjD2PnBh44AIQ6XUOCESOhXpEp3HrcGMwbjzQKMSaf63IJe", 1, 64, C8.pack "E2CCC7827F1DD7C33041A98906A8FD7BAE1920A55FCB8F831683F14F1C3979351CB868717E5AB342D9A11ACF0B12D3283931D609B06602DA33F8377D1F1F9902"), 
  (C8.pack "passDATAb00AB7YxDTTlRH2dqxDx19GDxDV1zFMz7E6QVqKIzwOtMnlxQLttpE5", C8.pack "saltKEYbcTcXHCBxtjD2PnBh44AIQ6XUOCESOhXpEp3HrcGMwbjzQKMSaf63IJe", 100000, 64, C8.pack "07447401C85766E4AED583DE2E6BF5A675EABE4F3618281C95616F4FC1FDFE6ECBC1C3982789D4FD941D6584EF534A78BD37AE02555D9455E8F089FDB4DFB6BB"), 
  (C8.pack "passDATAb00AB7YxDTTlRH2dqxDx19GDxDV1zFMz7E6QVqKIzwOtMnlxQLttpE57", C8.pack "saltKEYbcTcXHCBxtjD2PnBh44AIQ6XUOCESOhXpEp3HrcGMwbjzQKMSaf63IJem", 1, 64, C8.pack "B029A551117FF36977F283F579DC7065B352266EA243BDD3F920F24D4D141ED8B6E02D96E2D3BDFB76F8D77BA8F4BB548996AD85BB6F11D01A015CE518F9A717"), 
  (C8.pack "passDATAb00AB7YxDTTlRH2dqxDx19GDxDV1zFMz7E6QVqKIzwOtMnlxQLttpE57", C8.pack "saltKEYbcTcXHCBxtjD2PnBh44AIQ6XUOCESOhXpEp3HrcGMwbjzQKMSaf63IJem", 100000, 64, C8.pack "31F5CC83ED0E948C05A15735D818703AAA7BFF3F09F5169CAF5DBA6602A05A4D5CFF5553D42E82E40516D6DC157B8DAEAE61D3FEA456D964CB2F7F9A63BBBDB5"), 
  (C8.pack "passDATAb00AB7YxDTTlRH2dqxDx19GDxDV1zFMz7E6QVqKIzwOtMnlxQLttpE57U", C8.pack "saltKEYbcTcXHCBxtjD2PnBh44AIQ6XUOCESOhXpEp3HrcGMwbjzQKMSaf63IJemk", 1, 64, C8.pack "28B8A9F644D6800612197BB74DF460272E2276DE8CC07AC4897AC24DBC6EB77499FCAF97415244D9A29DA83FC347D09A5DBCFD6BD63FF6E410803DCA8A900AB6"), 
  (C8.pack "passDATAb00AB7YxDTTlRH2dqxDx19GDxDV1zFMz7E6QVqKIzwOtMnlxQLttpE57U", C8.pack "saltKEYbcTcXHCBxtjD2PnBh44AIQ6XUOCESOhXpEp3HrcGMwbjzQKMSaf63IJemk", 100000, 64, C8.pack "056BC9072A356B7D4DA60DD66F5968C2CAA375C0220EDA6B47EF8E8D105ED68B44185FE9003FBBA49E2C84240C9E8FD3F5B2F4F6512FD936450253DB37D10028"), 
  (C8.pack "passDATAb00AB7YxDTTlRH2dqxDx19GDxDV1zFMz7E6QVqKIzwOtMnlxQLttpE57Un4u12D2YD7oOPpiEvCDYvntXEe4NNPLCnGGeJArbYDEu6xDoCfWH6kbuV6awi0", C8.pack "saltKEYbcTcXHCBxtjD2PnBh44AIQ6XUOCESOhXpEp3HrcGMwbjzQKMSaf63IJemkURWoqHusIeVB8Il91NjiCGQacPUu9qTFaShLbKG0Yj4RCMV56WPj7E14EMpbxy", 1, 64, C8.pack "16226C85E4F8D604573008BFE61C10B6947B53990450612DD4A3077F7DEE2116229E68EFD1DF6D73BD3C6D07567790EEA1E8B2AE9A1B046BE593847D9441A1B7"), 
  (C8.pack "passDATAb00AB7YxDTTlRH2dqxDx19GDxDV1zFMz7E6QVqKIzwOtMnlxQLttpE57Un4u12D2YD7oOPpiEvCDYvntXEe4NNPLCnGGeJArbYDEu6xDoCfWH6kbuV6awi0", C8.pack "saltKEYbcTcXHCBxtjD2PnBh44AIQ6XUOCESOhXpEp3HrcGMwbjzQKMSaf63IJemkURWoqHusIeVB8Il91NjiCGQacPUu9qTFaShLbKG0Yj4RCMV56WPj7E14EMpbxy", 100000, 64, C8.pack "70CF39F14C4CAF3C81FA288FB46C1DB52D19F72722F7BC84F040676D3371C89C11C50F69BCFBC3ACB0AB9E92E4EF622727A916219554B2FA121BEDDA97FF3332"), 
  (C8.pack "passDATAb00AB7YxDTTlRH2dqxDx19GDxDV1zFMz7E6QVqKIzwOtMnlxQLttpE57Un4u12D2YD7oOPpiEvCDYvntXEe4NNPLCnGGeJArbYDEu6xDoCfWH6kbuV6awi04", C8.pack "saltKEYbcTcXHCBxtjD2PnBh44AIQ6XUOCESOhXpEp3HrcGMwbjzQKMSaf63IJemkURWoqHusIeVB8Il91NjiCGQacPUu9qTFaShLbKG0Yj4RCMV56WPj7E14EMpbxy6", 1, 64, C8.pack "880C58C316D3A5B9F05977AB9C60C10ABEEBFAD5CE89CAE62905C1C4F80A0A098D82F95321A6220F8AECCFB45CE6107140899E8D655306AE6396553E2851376C"), 
  (C8.pack "passDATAb00AB7YxDTTlRH2dqxDx19GDxDV1zFMz7E6QVqKIzwOtMnlxQLttpE57Un4u12D2YD7oOPpiEvCDYvntXEe4NNPLCnGGeJArbYDEu6xDoCfWH6kbuV6awi04", C8.pack "saltKEYbcTcXHCBxtjD2PnBh44AIQ6XUOCESOhXpEp3HrcGMwbjzQKMSaf63IJemkURWoqHusIeVB8Il91NjiCGQacPUu9qTFaShLbKG0Yj4RCMV56WPj7E14EMpbxy6", 100000, 64, C8.pack "2668B71B3CA56136B5E87F30E098F6B4371CB5ED95537C7A073DAC30A2D5BE52756ADF5BB2F4320CB11C4E16B24965A9C790DEF0CBC62906920B4F2EB84D1D4A"), 
  (C8.pack "passDATAb00AB7YxDTTlRH2dqxDx19GDxDV1zFMz7E6QVqKIzwOtMnlxQLttpE57Un4u12D2YD7oOPpiEvCDYvntXEe4NNPLCnGGeJArbYDEu6xDoCfWH6kbuV6awi04U", C8.pack "saltKEYbcTcXHCBxtjD2PnBh44AIQ6XUOCESOhXpEp3HrcGMwbjzQKMSaf63IJemkURWoqHusIeVB8Il91NjiCGQacPUu9qTFaShLbKG0Yj4RCMV56WPj7E14EMpbxy6P", 1, 64, C8.pack "93B9BA8283CC17D50EF3B44820828A258A996DE258225D24FB59990A6D0DE82DFB3FE2AC201952100E4CC8F06D883A9131419C0F6F5A6ECB8EC821545F14ADF1"), 
  (C8.pack "passDATAb00AB7YxDTTlRH2dqxDx19GDxDV1zFMz7E6QVqKIzwOtMnlxQLttpE57Un4u12D2YD7oOPpiEvCDYvntXEe4NNPLCnGGeJArbYDEu6xDoCfWH6kbuV6awi04U", C8.pack "saltKEYbcTcXHCBxtjD2PnBh44AIQ6XUOCESOhXpEp3HrcGMwbjzQKMSaf63IJemkURWoqHusIeVB8Il91NjiCGQacPUu9qTFaShLbKG0Yj4RCMV56WPj7E14EMpbxy6P", 100000, 64, C8.pack "2575B485AFDF37C260B8F3386D33A60ED929993C9D48AC516EC66B87E06BE54ADE7E7C8CB3417C81603B080A8EEFC56072811129737CED96236B9364E22CE3A5"), 
  (C8.pack "passDATAb00AB7YxDTTlRH2dqxDx19GDxDV1zFMz7E6QVqKIzwOtMnlxQLttpE57Un4u12D2YD7oOPpiEvCDYvntXEe4NNPLCnGGeJArbYDEu6xDoCfWH6kbuV6awi04Uz3ebEAhzZ4ve1A2wg5CnLXdZC5Y7gwfVgbEgZSTmoYQSzC5OW4dfrjqiwApTACO6xoOL1AjWj6X6f6qFfF8TVmOzU9RhOd1N4QtzWI4fP6FYttNz5FuLdtYVXWVXH2Tf7I9fieMeWCHTMkM4VcmQyQHpbcP8MEb5f1g6Ckg5xk3HQr3wMBvQcOHpCPy1K8HCM7a5wkPDhgVA0BVmwNpsRIbDQZRtHK6dT6bGyalp6gbFZBuBHwD86gTzkrFY7HkOVrgc0gJcGJZe65Ce8v4Jn5OzkuVsiU8efm2Pw2RnbpWSAr7SkVdCwXK2XSJDQ5fZ4HBEz9VTFYrG23ELuLjvx5njOLNgDAJuf5JB2tn4nMjjcnl1e8qcYVwZqFzEv2zhLyDWMkV4tzl4asLnvyAxTBkxPRZj2pRABWwb3kEofpsHYxMTAn38YSpZreoXipZWBnu6HDURaruXaIPYFPYHl9Ls9wsuD7rzaGfbOyfVgLIGK5rODphwRA7lm88bGKY8b7tWOtepyEvaLxMI7GZF5ScwpZTYeEDNUKPzvM2Im9zehIaznpguNdNXNMLWnwPu4H6zEvajkw3G3ucSiXKmh6XNe3hkdSANm3vnxzRXm4fcuzAx68IElXE2bkGFElluDLo6EsUDWZ4JIWBVaDwYdJx8uCXbQdoifzCs5kuuClaDaDqIhb5hJ2WR8mxiueFsS0aDGdIYmye5svmNmzQxFmdOkHoF7CfwuU1yy4uEEt9vPSP2wFp1dyaMvJW68vtB4kddLmI6gIgVVcT6ZX1Qm6WsusPrdisPLB2ScodXojCbL3DLj6PKG8QDVMWTrL1TpafT2wslRledWIhsTlv2mI3C066WMcTSwKLXdEDhVvFJ6ShiLKSN7gnRrlE0BnAw", C8.pack "saltKEYbcTcXHCBxtjD2PnBh44AIQ6XUOCESOhXpEp3HrcGMwbjzQKMSaf63IJemkURWoqHusIeVB8Il91NjiCGQacPUu9qTFaShLbKG0Yj4RCMV56WPj7E14EMpbxy6PlBdILBOkKUB6TGTPJXh1tpdOHTG6KuIvcbQp9qWjaf1uxAKgiTtYRIHhxjJI2viVa6fDZ67QOouOaf2RXQhpsWaTtAVnff6PIFcvJhdPDFGV5nvmZWoCZQodj6yXRDHPw9PyF0iLYm9uFtEunlAAxGB5qqea4X5tZvB1OfLVwymY3a3JPjdxTdvHxCHbqqE0zip61JNqdmeWxGtlRBC6CGoCiHO4XxHCntQBRJDcG0zW7joTdgtTBarsQQhlLXBGMNBSNmmTbDf3hFtawUBCJH18IAiRMwyeQJbJ2bERsY3MVRPuYCf4Au7gN72iGh1lRktSQtEFye7pO46kMXRrEjHQWXInMzzy7X2StXUzHVTFF2VdOoKn0WUqFNvB6PF7qIsOlYKj57bi1Psa34s85WxMSbTkhrd7VHdHZkTVaWdraohXYOePdeEvIwObCGEXkETUzqM5P2yzoBOJSdjpIYaa8zzdLD3yrb1TwCZuJVxsrq0XXY6vErU4QntsW0972XmGNyumFNJiPm4ONKh1RLvS1kddY3nm8276S4TUuZfrRQO8QxZRNuSaZI8JRZp5VojB5DktuMxAQkqoPjQ5Vtb6oXeOyY591CB1MEW1fLTCs0NrL321SaNRMqza1ETogAxpEiYwZ6pIgnMmSqNMRdZnCqA4gMWw1lIVATWK83OCeicNRUNOdfzS7A8vbLcmvKPtpOFvhNzwrrUdkvuKvaYJviQgeR7snGetO9JLCwIlHIj52gMCNU18d32SJl7Xomtl3wIe02SMvq1i1BcaX7lXioqWGmgVqBWU3fsUuGwHi6RUKCCQdEOBfNo2WdpFaCflcgnn0O6jVHCqkv8cQk81AqS00rAmHGCNTwyA6Tq5TXoLlDnC8gAQjDUsZp0z", 1, 64, C8.pack "384BCD6914407E40C295D1037CF4F990E8F0E720AF43CB706683177016D36D1A14B3A7CF22B5DF8D5D7D44D69610B64251ADE2E7AB54A3813A89935592E391BF"), 
  (C8.pack "passDATAb00AB7YxDTTlRH2dqxDx19GDxDV1zFMz7E6QVqKIzwOtMnlxQLttpE57Un4u12D2YD7oOPpiEvCDYvntXEe4NNPLCnGGeJArbYDEu6xDoCfWH6kbuV6awi04Uz3ebEAhzZ4ve1A2wg5CnLXdZC5Y7gwfVgbEgZSTmoYQSzC5OW4dfrjqiwApTACO6xoOL1AjWj6X6f6qFfF8TVmOzU9RhOd1N4QtzWI4fP6FYttNz5FuLdtYVXWVXH2Tf7I9fieMeWCHTMkM4VcmQyQHpbcP8MEb5f1g6Ckg5xk3HQr3wMBvQcOHpCPy1K8HCM7a5wkPDhgVA0BVmwNpsRIbDQZRtHK6dT6bGyalp6gbFZBuBHwD86gTzkrFY7HkOVrgc0gJcGJZe65Ce8v4Jn5OzkuVsiU8efm2Pw2RnbpWSAr7SkVdCwXK2XSJDQ5fZ4HBEz9VTFYrG23ELuLjvx5njOLNgDAJuf5JB2tn4nMjjcnl1e8qcYVwZqFzEv2zhLyDWMkV4tzl4asLnvyAxTBkxPRZj2pRABWwb3kEofpsHYxMTAn38YSpZreoXipZWBnu6HDURaruXaIPYFPYHl9Ls9wsuD7rzaGfbOyfVgLIGK5rODphwRA7lm88bGKY8b7tWOtepyEvaLxMI7GZF5ScwpZTYeEDNUKPzvM2Im9zehIaznpguNdNXNMLWnwPu4H6zEvajkw3G3ucSiXKmh6XNe3hkdSANm3vnxzRXm4fcuzAx68IElXE2bkGFElluDLo6EsUDWZ4JIWBVaDwYdJx8uCXbQdoifzCs5kuuClaDaDqIhb5hJ2WR8mxiueFsS0aDGdIYmye5svmNmzQxFmdOkHoF7CfwuU1yy4uEEt9vPSP2wFp1dyaMvJW68vtB4kddLmI6gIgVVcT6ZX1Qm6WsusPrdisPLB2ScodXojCbL3DLj6PKG8QDVMWTrL1TpafT2wslRledWIhsTlv2mI3C066WMcTSwKLXdEDhVvFJ6ShiLKSN7gnRrlE0BnAw", C8.pack "saltKEYbcTcXHCBxtjD2PnBh44AIQ6XUOCESOhXpEp3HrcGMwbjzQKMSaf63IJemkURWoqHusIeVB8Il91NjiCGQacPUu9qTFaShLbKG0Yj4RCMV56WPj7E14EMpbxy6PlBdILBOkKUB6TGTPJXh1tpdOHTG6KuIvcbQp9qWjaf1uxAKgiTtYRIHhxjJI2viVa6fDZ67QOouOaf2RXQhpsWaTtAVnff6PIFcvJhdPDFGV5nvmZWoCZQodj6yXRDHPw9PyF0iLYm9uFtEunlAAxGB5qqea4X5tZvB1OfLVwymY3a3JPjdxTdvHxCHbqqE0zip61JNqdmeWxGtlRBC6CGoCiHO4XxHCntQBRJDcG0zW7joTdgtTBarsQQhlLXBGMNBSNmmTbDf3hFtawUBCJH18IAiRMwyeQJbJ2bERsY3MVRPuYCf4Au7gN72iGh1lRktSQtEFye7pO46kMXRrEjHQWXInMzzy7X2StXUzHVTFF2VdOoKn0WUqFNvB6PF7qIsOlYKj57bi1Psa34s85WxMSbTkhrd7VHdHZkTVaWdraohXYOePdeEvIwObCGEXkETUzqM5P2yzoBOJSdjpIYaa8zzdLD3yrb1TwCZuJVxsrq0XXY6vErU4QntsW0972XmGNyumFNJiPm4ONKh1RLvS1kddY3nm8276S4TUuZfrRQO8QxZRNuSaZI8JRZp5VojB5DktuMxAQkqoPjQ5Vtb6oXeOyY591CB1MEW1fLTCs0NrL321SaNRMqza1ETogAxpEiYwZ6pIgnMmSqNMRdZnCqA4gMWw1lIVATWK83OCeicNRUNOdfzS7A8vbLcmvKPtpOFvhNzwrrUdkvuKvaYJviQgeR7snGetO9JLCwIlHIj52gMCNU18d32SJl7Xomtl3wIe02SMvq1i1BcaX7lXioqWGmgVqBWU3fsUuGwHi6RUKCCQdEOBfNo2WdpFaCflcgnn0O6jVHCqkv8cQk81AqS00rAmHGCNTwyA6Tq5TXoLlDnC8gAQjDUsZp0z", 100000, 64, C8.pack "B8674F6C0CC9F8CF1F1874534FD5AF01FC1504D76C2BC2AA0A75FE4DD5DFD1DAF60EA7C85F122BCEEB8772659D601231607726998EAC3F6AAB72EFF7BA349F7F"), 
  (C8.pack "passDATAb00AB7YxDTT", C8.pack "saltKEYbcTcXHCBxtjD", 1, 63, C8.pack "CBE6088AD4359AF42E603C2A33760EF9D4017A7B2AAD10AF46F992C660A0B461ECB0DC2A79C2570941BEA6A08D15D6887E79F32B132E1C134E9525EEDDD744"), 
  (C8.pack "passDATAb00AB7YxDTT", C8.pack "saltKEYbcTcXHCBxtjD", 100000, 63, C8.pack "ACCDCD8798AE5CD85804739015EF2A11E32591B7B7D16F76819B30B0D49D80E1ABEA6C9822B80A1FDFE421E26F5603ECA8A47A64C9A004FB5AF8229F762FF4"), 
  (C8.pack "passDATAb00AB7YxDTTl", C8.pack "saltKEYbcTcXHCBxtjD2", 1, 63, C8.pack "8E5074A9513C1F1512C9B1DF1D8BFFA9D8B4EF9105DFC16681222839560FB63264BED6AABF761F180E912A66E0B53D65EC88F6A1519E14804EBA6DC9DF1370"), 
  (C8.pack "passDATAb00AB7YxDTTl", C8.pack "saltKEYbcTcXHCBxtjD2", 100000, 63, C8.pack "594256B0BD4D6C9F21A87F7BA5772A791A10E6110694F44365CD94670E57F1AECD797EF1D1001938719044C7F018026697845EB9AD97D97DE36AB8786AAB50"), 
  (C8.pack "passDATAb00AB7YxDTTlR", C8.pack "saltKEYbcTcXHCBxtjD2P", 1, 63, C8.pack "A6AC8C048A7DFD7B838DA88F22C3FAB5BFF15D7CB8D83A62C6721A8FAF6903EAB6152CB7421026E36F2FFEF661EB4384DC276495C71B5CAB72E1C1A38712E5"), 
  (C8.pack "passDATAb00AB7YxDTTlR", C8.pack "saltKEYbcTcXHCBxtjD2P", 100000, 63, C8.pack "94FFC2B1A390B7B8A9E6A44922C330DB2B193ADCF082EECD06057197F35931A9D0EC0EE5C660744B50B61F23119B847E658D179A914807F4B8AB8EB9505AF0"), 
  (C8.pack "passDATAb00AB7YxDTTlRH2dqxDx19GDxDV1zFMz7E6QVqKIzwOtMnlxQLttpE5", C8.pack "saltKEYbcTcXHCBxtjD2PnBh44AIQ6XUOCESOhXpEp3HrcGMwbjzQKMSaf63IJe", 1, 63, C8.pack "E2CCC7827F1DD7C33041A98906A8FD7BAE1920A55FCB8F831683F14F1C3979351CB868717E5AB342D9A11ACF0B12D3283931D609B06602DA33F8377D1F1F99"), 
  (C8.pack "passDATAb00AB7YxDTTlRH2dqxDx19GDxDV1zFMz7E6QVqKIzwOtMnlxQLttpE5", C8.pack "saltKEYbcTcXHCBxtjD2PnBh44AIQ6XUOCESOhXpEp3HrcGMwbjzQKMSaf63IJe", 100000, 63, C8.pack "07447401C85766E4AED583DE2E6BF5A675EABE4F3618281C95616F4FC1FDFE6ECBC1C3982789D4FD941D6584EF534A78BD37AE02555D9455E8F089FDB4DFB6"), 
  (C8.pack "passDATAb00AB7YxDTTlRH2dqxDx19GDxDV1zFMz7E6QVqKIzwOtMnlxQLttpE57", C8.pack "saltKEYbcTcXHCBxtjD2PnBh44AIQ6XUOCESOhXpEp3HrcGMwbjzQKMSaf63IJem", 1, 63, C8.pack "B029A551117FF36977F283F579DC7065B352266EA243BDD3F920F24D4D141ED8B6E02D96E2D3BDFB76F8D77BA8F4BB548996AD85BB6F11D01A015CE518F9A7"), 
  (C8.pack "passDATAb00AB7YxDTTlRH2dqxDx19GDxDV1zFMz7E6QVqKIzwOtMnlxQLttpE57", C8.pack "saltKEYbcTcXHCBxtjD2PnBh44AIQ6XUOCESOhXpEp3HrcGMwbjzQKMSaf63IJem", 100000, 63, C8.pack "31F5CC83ED0E948C05A15735D818703AAA7BFF3F09F5169CAF5DBA6602A05A4D5CFF5553D42E82E40516D6DC157B8DAEAE61D3FEA456D964CB2F7F9A63BBBD"), 
  (C8.pack "passDATAb00AB7YxDTTlRH2dqxDx19GDxDV1zFMz7E6QVqKIzwOtMnlxQLttpE57U", C8.pack "saltKEYbcTcXHCBxtjD2PnBh44AIQ6XUOCESOhXpEp3HrcGMwbjzQKMSaf63IJemk", 1, 63, C8.pack "28B8A9F644D6800612197BB74DF460272E2276DE8CC07AC4897AC24DBC6EB77499FCAF97415244D9A29DA83FC347D09A5DBCFD6BD63FF6E410803DCA8A900A"), 
  (C8.pack "passDATAb00AB7YxDTTlRH2dqxDx19GDxDV1zFMz7E6QVqKIzwOtMnlxQLttpE57U", C8.pack "saltKEYbcTcXHCBxtjD2PnBh44AIQ6XUOCESOhXpEp3HrcGMwbjzQKMSaf63IJemk", 100000, 63, C8.pack "056BC9072A356B7D4DA60DD66F5968C2CAA375C0220EDA6B47EF8E8D105ED68B44185FE9003FBBA49E2C84240C9E8FD3F5B2F4F6512FD936450253DB37D100"), 
  (C8.pack "passDATAb00AB7YxDTTlRH2dqxDx19GDxDV1zFMz7E6QVqKIzwOtMnlxQLttpE57Un4u12D2YD7oOPpiEvCDYvntXEe4NNPLCnGGeJArbYDEu6xDoCfWH6kbuV6awi0", C8.pack "saltKEYbcTcXHCBxtjD2PnBh44AIQ6XUOCESOhXpEp3HrcGMwbjzQKMSaf63IJemkURWoqHusIeVB8Il91NjiCGQacPUu9qTFaShLbKG0Yj4RCMV56WPj7E14EMpbxy", 1, 63, C8.pack "16226C85E4F8D604573008BFE61C10B6947B53990450612DD4A3077F7DEE2116229E68EFD1DF6D73BD3C6D07567790EEA1E8B2AE9A1B046BE593847D9441A1"), 
  (C8.pack "passDATAb00AB7YxDTTlRH2dqxDx19GDxDV1zFMz7E6QVqKIzwOtMnlxQLttpE57Un4u12D2YD7oOPpiEvCDYvntXEe4NNPLCnGGeJArbYDEu6xDoCfWH6kbuV6awi0", C8.pack "saltKEYbcTcXHCBxtjD2PnBh44AIQ6XUOCESOhXpEp3HrcGMwbjzQKMSaf63IJemkURWoqHusIeVB8Il91NjiCGQacPUu9qTFaShLbKG0Yj4RCMV56WPj7E14EMpbxy", 100000, 63, C8.pack "70CF39F14C4CAF3C81FA288FB46C1DB52D19F72722F7BC84F040676D3371C89C11C50F69BCFBC3ACB0AB9E92E4EF622727A916219554B2FA121BEDDA97FF33"), 
  (C8.pack "passDATAb00AB7YxDTTlRH2dqxDx19GDxDV1zFMz7E6QVqKIzwOtMnlxQLttpE57Un4u12D2YD7oOPpiEvCDYvntXEe4NNPLCnGGeJArbYDEu6xDoCfWH6kbuV6awi04", C8.pack "saltKEYbcTcXHCBxtjD2PnBh44AIQ6XUOCESOhXpEp3HrcGMwbjzQKMSaf63IJemkURWoqHusIeVB8Il91NjiCGQacPUu9qTFaShLbKG0Yj4RCMV56WPj7E14EMpbxy6", 1, 63, C8.pack "880C58C316D3A5B9F05977AB9C60C10ABEEBFAD5CE89CAE62905C1C4F80A0A098D82F95321A6220F8AECCFB45CE6107140899E8D655306AE6396553E285137"), 
  (C8.pack "passDATAb00AB7YxDTTlRH2dqxDx19GDxDV1zFMz7E6QVqKIzwOtMnlxQLttpE57Un4u12D2YD7oOPpiEvCDYvntXEe4NNPLCnGGeJArbYDEu6xDoCfWH6kbuV6awi04", C8.pack "saltKEYbcTcXHCBxtjD2PnBh44AIQ6XUOCESOhXpEp3HrcGMwbjzQKMSaf63IJemkURWoqHusIeVB8Il91NjiCGQacPUu9qTFaShLbKG0Yj4RCMV56WPj7E14EMpbxy6", 100000, 63, C8.pack "2668B71B3CA56136B5E87F30E098F6B4371CB5ED95537C7A073DAC30A2D5BE52756ADF5BB2F4320CB11C4E16B24965A9C790DEF0CBC62906920B4F2EB84D1D"), 
  (C8.pack "passDATAb00AB7YxDTTlRH2dqxDx19GDxDV1zFMz7E6QVqKIzwOtMnlxQLttpE57Un4u12D2YD7oOPpiEvCDYvntXEe4NNPLCnGGeJArbYDEu6xDoCfWH6kbuV6awi04U", C8.pack "saltKEYbcTcXHCBxtjD2PnBh44AIQ6XUOCESOhXpEp3HrcGMwbjzQKMSaf63IJemkURWoqHusIeVB8Il91NjiCGQacPUu9qTFaShLbKG0Yj4RCMV56WPj7E14EMpbxy6P", 1, 63, C8.pack "93B9BA8283CC17D50EF3B44820828A258A996DE258225D24FB59990A6D0DE82DFB3FE2AC201952100E4CC8F06D883A9131419C0F6F5A6ECB8EC821545F14AD"), 
  (C8.pack "passDATAb00AB7YxDTTlRH2dqxDx19GDxDV1zFMz7E6QVqKIzwOtMnlxQLttpE57Un4u12D2YD7oOPpiEvCDYvntXEe4NNPLCnGGeJArbYDEu6xDoCfWH6kbuV6awi04U", C8.pack "saltKEYbcTcXHCBxtjD2PnBh44AIQ6XUOCESOhXpEp3HrcGMwbjzQKMSaf63IJemkURWoqHusIeVB8Il91NjiCGQacPUu9qTFaShLbKG0Yj4RCMV56WPj7E14EMpbxy6P", 100000, 63, C8.pack "2575B485AFDF37C260B8F3386D33A60ED929993C9D48AC516EC66B87E06BE54ADE7E7C8CB3417C81603B080A8EEFC56072811129737CED96236B9364E22CE3"), 
      (C8.pack "passDATAb00AB7YxDTTlRH2dqxDx19GDxDV1zFMz7E6QVqKIzwOtMnlxQLttpE57Un4u12D2YD7oOPpiEvCDYvntXEe4NNPLCnGGeJArbYDEu6xDoCfWH6kbuV6awi04Uz3ebEAhzZ4ve1A2wg5CnLXdZC5Y7gwfVgbEgZSTmoYQSzC5OW4dfrjqiwApTACO6xoOL1AjWj6X6f6qFfF8TVmOzU9RhOd1N4QtzWI4fP6FYttNz5FuLdtYVXWVXH2Tf7I9fieMeWCHTMkM4VcmQyQHpbcP8MEb5f1g6Ckg5xk3HQr3wMBvQcOHpCPy1K8HCM7a5wkPDhgVA0BVmwNpsRIbDQZRtHK6dT6bGyalp6gbFZBuBHwD86gTzkrFY7HkOVrgc0gJcGJZe65Ce8v4Jn5OzkuVsiU8efm2Pw2RnbpWSAr7SkVdCwXK2XSJDQ5fZ4HBEz9VTFYrG23ELuLjvx5njOLNgDAJuf5JB2tn4nMjjcnl1e8qcYVwZqFzEv2zhLyDWMkV4tzl4asLnvyAxTBkxPRZj2pRABWwb3kEofpsHYxMTAn38YSpZreoXipZWBnu6HDURaruXaIPYFPYHl9Ls9wsuD7rzaGfbOyfVgLIGK5rODphwRA7lm88bGKY8b7tWOtepyEvaLxMI7GZF5ScwpZTYeEDNUKPzvM2Im9zehIaznpguNdNXNMLWnwPu4H6zEvajkw3G3ucSiXKmh6XNe3hkdSANm3vnxzRXm4fcuzAx68IElXE2bkGFElluDLo6EsUDWZ4JIWBVaDwYdJx8uCXbQdoifzCs5kuuClaDaDqIhb5hJ2WR8mxiueFsS0aDGdIYmye5svmNmzQxFmdOkHoF7CfwuU1yy4uEEt9vPSP2wFp1dyaMvJW68vtB4kddLmI6gIgVVcT6ZX1Qm6WsusPrdisPLB2ScodXojCbL3DLj6PKG8QDVMWTrL1TpafT2wslRledWIhsTlv2mI3C066WMcTSwKLXdEDhVvFJ6ShiLKSN7gnRrlE0BnAw", C8.pack "saltKEYbcTcXHCBxtjD2PnBh44AIQ6XUOCESOhXpEp3HrcGMwbjzQKMSaf63IJemkURWoqHusIeVB8Il91NjiCGQacPUu9qTFaShLbKG0Yj4RCMV56WPj7E14EMpbxy6PlBdILBOkKUB6TGTPJXh1tpdOHTG6KuIvcbQp9qWjaf1uxAKgiTtYRIHhxjJI2viVa6fDZ67QOouOaf2RXQhpsWaTtAVnff6PIFcvJhdPDFGV5nvmZWoCZQodj6yXRDHPw9PyF0iLYm9uFtEunlAAxGB5qqea4X5tZvB1OfLVwymY3a3JPjdxTdvHxCHbqqE0zip61JNqdmeWxGtlRBC6CGoCiHO4XxHCntQBRJDcG0zW7joTdgtTBarsQQhlLXBGMNBSNmmTbDf3hFtawUBCJH18IAiRMwyeQJbJ2bERsY3MVRPuYCf4Au7gN72iGh1lRktSQtEFye7pO46kMXRrEjHQWXInMzzy7X2StXUzHVTFF2VdOoKn0WUqFNvB6PF7qIsOlYKj57bi1Psa34s85WxMSbTkhrd7VHdHZkTVaWdraohXYOePdeEvIwObCGEXkETUzqM5P2yzoBOJSdjpIYaa8zzdLD3yrb1TwCZuJVxsrq0XXY6vErU4QntsW0972XmGNyumFNJiPm4ONKh1RLvS1kddY3nm8276S4TUuZfrRQO8QxZRNuSaZI8JRZp5VojB5DktuMxAQkqoPjQ5Vtb6oXeOyY591CB1MEW1fLTCs0NrL321SaNRMqza1ETogAxpEiYwZ6pIgnMmSqNMRdZnCqA4gMWw1lIVATWK83OCeicNRUNOdfzS7A8vbLcmvKPtpOFvhNzwrrUdkvuKvaYJviQgeR7snGetO9JLCwIlHIj52gMCNU18d32SJl7Xomtl3wIe02SMvq1i1BcaX7lXioqWGmgVqBWU3fsUuGwHi6RUKCCQdEOBfNo2WdpFaCflcgnn0O6jVHCqkv8cQk81AqS00rAmHGCNTwyA6Tq5TXoLlDnC8gAQjDUsZp0z", 100000, 63, C8.pack "B8674F6C0CC9F8CF1F1874534FD5AF01FC1504D76C2BC2AA0A75FE4DD5DFD1DAF60EA7C85F122BCEEB8772659D601231607726998EAC3F6AAB72EFF7BA349F"), 
  (C8.pack "passDATAb00AB7YxDTT", C8.pack "saltKEYbcTcXHCBxtjD", 1, 65, C8.pack "CBE6088AD4359AF42E603C2A33760EF9D4017A7B2AAD10AF46F992C660A0B461ECB0DC2A79C2570941BEA6A08D15D6887E79F32B132E1C134E9525EEDDD744FA88"), 
  (C8.pack "passDATAb00AB7YxDTT", C8.pack "saltKEYbcTcXHCBxtjD", 100000, 65, C8.pack "ACCDCD8798AE5CD85804739015EF2A11E32591B7B7D16F76819B30B0D49D80E1ABEA6C9822B80A1FDFE421E26F5603ECA8A47A64C9A004FB5AF8229F762FF41F7C"), 
  (C8.pack "passDATAb00AB7YxDTTl", C8.pack "saltKEYbcTcXHCBxtjD2", 1, 65, C8.pack "8E5074A9513C1F1512C9B1DF1D8BFFA9D8B4EF9105DFC16681222839560FB63264BED6AABF761F180E912A66E0B53D65EC88F6A1519E14804EBA6DC9DF1370070B"), 
  (C8.pack "passDATAb00AB7YxDTTl", C8.pack "saltKEYbcTcXHCBxtjD2", 100000, 65, C8.pack "594256B0BD4D6C9F21A87F7BA5772A791A10E6110694F44365CD94670E57F1AECD797EF1D1001938719044C7F018026697845EB9AD97D97DE36AB8786AAB5096E7"), 
  (C8.pack "passDATAb00AB7YxDTTlR", C8.pack "saltKEYbcTcXHCBxtjD2P", 1, 65, C8.pack "A6AC8C048A7DFD7B838DA88F22C3FAB5BFF15D7CB8D83A62C6721A8FAF6903EAB6152CB7421026E36F2FFEF661EB4384DC276495C71B5CAB72E1C1A38712E56B93"), 
  (C8.pack "passDATAb00AB7YxDTTlR", C8.pack "saltKEYbcTcXHCBxtjD2P", 100000, 65, C8.pack "94FFC2B1A390B7B8A9E6A44922C330DB2B193ADCF082EECD06057197F35931A9D0EC0EE5C660744B50B61F23119B847E658D179A914807F4B8AB8EB9505AF06526"), 
  (C8.pack "passDATAb00AB7YxDTTlRH2dqxDx19GDxDV1zFMz7E6QVqKIzwOtMnlxQLttpE5", C8.pack "saltKEYbcTcXHCBxtjD2PnBh44AIQ6XUOCESOhXpEp3HrcGMwbjzQKMSaf63IJe", 1, 65, C8.pack "E2CCC7827F1DD7C33041A98906A8FD7BAE1920A55FCB8F831683F14F1C3979351CB868717E5AB342D9A11ACF0B12D3283931D609B06602DA33F8377D1F1F9902DA"), 
  (C8.pack "passDATAb00AB7YxDTTlRH2dqxDx19GDxDV1zFMz7E6QVqKIzwOtMnlxQLttpE5", C8.pack "saltKEYbcTcXHCBxtjD2PnBh44AIQ6XUOCESOhXpEp3HrcGMwbjzQKMSaf63IJe", 100000, 65, C8.pack "07447401C85766E4AED583DE2E6BF5A675EABE4F3618281C95616F4FC1FDFE6ECBC1C3982789D4FD941D6584EF534A78BD37AE02555D9455E8F089FDB4DFB6BB30"), 
  (C8.pack "passDATAb00AB7YxDTTlRH2dqxDx19GDxDV1zFMz7E6QVqKIzwOtMnlxQLttpE57", C8.pack "saltKEYbcTcXHCBxtjD2PnBh44AIQ6XUOCESOhXpEp3HrcGMwbjzQKMSaf63IJem", 1, 65, C8.pack "B029A551117FF36977F283F579DC7065B352266EA243BDD3F920F24D4D141ED8B6E02D96E2D3BDFB76F8D77BA8F4BB548996AD85BB6F11D01A015CE518F9A71780"), 
  (C8.pack "passDATAb00AB7YxDTTlRH2dqxDx19GDxDV1zFMz7E6QVqKIzwOtMnlxQLttpE57", C8.pack "saltKEYbcTcXHCBxtjD2PnBh44AIQ6XUOCESOhXpEp3HrcGMwbjzQKMSaf63IJem", 100000, 65, C8.pack "31F5CC83ED0E948C05A15735D818703AAA7BFF3F09F5169CAF5DBA6602A05A4D5CFF5553D42E82E40516D6DC157B8DAEAE61D3FEA456D964CB2F7F9A63BBBDB59F"), 
  (C8.pack "passDATAb00AB7YxDTTlRH2dqxDx19GDxDV1zFMz7E6QVqKIzwOtMnlxQLttpE57U", C8.pack "saltKEYbcTcXHCBxtjD2PnBh44AIQ6XUOCESOhXpEp3HrcGMwbjzQKMSaf63IJemk", 1, 65, C8.pack "28B8A9F644D6800612197BB74DF460272E2276DE8CC07AC4897AC24DBC6EB77499FCAF97415244D9A29DA83FC347D09A5DBCFD6BD63FF6E410803DCA8A900AB671"), 
  (C8.pack "passDATAb00AB7YxDTTlRH2dqxDx19GDxDV1zFMz7E6QVqKIzwOtMnlxQLttpE57U", C8.pack "saltKEYbcTcXHCBxtjD2PnBh44AIQ6XUOCESOhXpEp3HrcGMwbjzQKMSaf63IJemk", 100000, 65, C8.pack "056BC9072A356B7D4DA60DD66F5968C2CAA375C0220EDA6B47EF8E8D105ED68B44185FE9003FBBA49E2C84240C9E8FD3F5B2F4F6512FD936450253DB37D1002889"), 
  (C8.pack "passDATAb00AB7YxDTTlRH2dqxDx19GDxDV1zFMz7E6QVqKIzwOtMnlxQLttpE57Un4u12D2YD7oOPpiEvCDYvntXEe4NNPLCnGGeJArbYDEu6xDoCfWH6kbuV6awi0", C8.pack "saltKEYbcTcXHCBxtjD2PnBh44AIQ6XUOCESOhXpEp3HrcGMwbjzQKMSaf63IJemkURWoqHusIeVB8Il91NjiCGQacPUu9qTFaShLbKG0Yj4RCMV56WPj7E14EMpbxy", 1, 65, C8.pack "16226C85E4F8D604573008BFE61C10B6947B53990450612DD4A3077F7DEE2116229E68EFD1DF6D73BD3C6D07567790EEA1E8B2AE9A1B046BE593847D9441A1B766"), 
  (C8.pack "passDATAb00AB7YxDTTlRH2dqxDx19GDxDV1zFMz7E6QVqKIzwOtMnlxQLttpE57Un4u12D2YD7oOPpiEvCDYvntXEe4NNPLCnGGeJArbYDEu6xDoCfWH6kbuV6awi0", C8.pack "saltKEYbcTcXHCBxtjD2PnBh44AIQ6XUOCESOhXpEp3HrcGMwbjzQKMSaf63IJemkURWoqHusIeVB8Il91NjiCGQacPUu9qTFaShLbKG0Yj4RCMV56WPj7E14EMpbxy", 100000, 65, C8.pack "70CF39F14C4CAF3C81FA288FB46C1DB52D19F72722F7BC84F040676D3371C89C11C50F69BCFBC3ACB0AB9E92E4EF622727A916219554B2FA121BEDDA97FF3332EC"), 
  (C8.pack "passDATAb00AB7YxDTTlRH2dqxDx19GDxDV1zFMz7E6QVqKIzwOtMnlxQLttpE57Un4u12D2YD7oOPpiEvCDYvntXEe4NNPLCnGGeJArbYDEu6xDoCfWH6kbuV6awi04", C8.pack "saltKEYbcTcXHCBxtjD2PnBh44AIQ6XUOCESOhXpEp3HrcGMwbjzQKMSaf63IJemkURWoqHusIeVB8Il91NjiCGQacPUu9qTFaShLbKG0Yj4RCMV56WPj7E14EMpbxy6", 1, 65, C8.pack "880C58C316D3A5B9F05977AB9C60C10ABEEBFAD5CE89CAE62905C1C4F80A0A098D82F95321A6220F8AECCFB45CE6107140899E8D655306AE6396553E2851376C57"), 
  (C8.pack "passDATAb00AB7YxDTTlRH2dqxDx19GDxDV1zFMz7E6QVqKIzwOtMnlxQLttpE57Un4u12D2YD7oOPpiEvCDYvntXEe4NNPLCnGGeJArbYDEu6xDoCfWH6kbuV6awi04", C8.pack "saltKEYbcTcXHCBxtjD2PnBh44AIQ6XUOCESOhXpEp3HrcGMwbjzQKMSaf63IJemkURWoqHusIeVB8Il91NjiCGQacPUu9qTFaShLbKG0Yj4RCMV56WPj7E14EMpbxy6", 100000, 65, C8.pack "2668B71B3CA56136B5E87F30E098F6B4371CB5ED95537C7A073DAC30A2D5BE52756ADF5BB2F4320CB11C4E16B24965A9C790DEF0CBC62906920B4F2EB84D1D4A30"), 
  (C8.pack "passDATAb00AB7YxDTTlRH2dqxDx19GDxDV1zFMz7E6QVqKIzwOtMnlxQLttpE57Un4u12D2YD7oOPpiEvCDYvntXEe4NNPLCnGGeJArbYDEu6xDoCfWH6kbuV6awi04U", C8.pack "saltKEYbcTcXHCBxtjD2PnBh44AIQ6XUOCESOhXpEp3HrcGMwbjzQKMSaf63IJemkURWoqHusIeVB8Il91NjiCGQacPUu9qTFaShLbKG0Yj4RCMV56WPj7E14EMpbxy6P", 1, 65, C8.pack "93B9BA8283CC17D50EF3B44820828A258A996DE258225D24FB59990A6D0DE82DFB3FE2AC201952100E4CC8F06D883A9131419C0F6F5A6ECB8EC821545F14ADF199"), 
  (C8.pack "passDATAb00AB7YxDTTlRH2dqxDx19GDxDV1zFMz7E6QVqKIzwOtMnlxQLttpE57Un4u12D2YD7oOPpiEvCDYvntXEe4NNPLCnGGeJArbYDEu6xDoCfWH6kbuV6awi04U", C8.pack "saltKEYbcTcXHCBxtjD2PnBh44AIQ6XUOCESOhXpEp3HrcGMwbjzQKMSaf63IJemkURWoqHusIeVB8Il91NjiCGQacPUu9qTFaShLbKG0Yj4RCMV56WPj7E14EMpbxy6P", 100000, 65, C8.pack "2575B485AFDF37C260B8F3386D33A60ED929993C9D48AC516EC66B87E06BE54ADE7E7C8CB3417C81603B080A8EEFC56072811129737CED96236B9364E22CE3A542"), 
  (C8.pack "passDATAb00AB7YxDTTlRH2dqxDx19GDxDV1zFMz7E6QVqKIzwOtMnlxQLttpE57Un4u12D2YD7oOPpiEvCDYvntXEe4NNPLCnGGeJArbYDEu6xDoCfWH6kbuV6awi04Uz3ebEAhzZ4ve1A2wg5CnLXdZC5Y7gwfVgbEgZSTmoYQSzC5OW4dfrjqiwApTACO6xoOL1AjWj6X6f6qFfF8TVmOzU9RhOd1N4QtzWI4fP6FYttNz5FuLdtYVXWVXH2Tf7I9fieMeWCHTMkM4VcmQyQHpbcP8MEb5f1g6Ckg5xk3HQr3wMBvQcOHpCPy1K8HCM7a5wkPDhgVA0BVmwNpsRIbDQZRtHK6dT6bGyalp6gbFZBuBHwD86gTzkrFY7HkOVrgc0gJcGJZe65Ce8v4Jn5OzkuVsiU8efm2Pw2RnbpWSAr7SkVdCwXK2XSJDQ5fZ4HBEz9VTFYrG23ELuLjvx5njOLNgDAJuf5JB2tn4nMjjcnl1e8qcYVwZqFzEv2zhLyDWMkV4tzl4asLnvyAxTBkxPRZj2pRABWwb3kEofpsHYxMTAn38YSpZreoXipZWBnu6HDURaruXaIPYFPYHl9Ls9wsuD7rzaGfbOyfVgLIGK5rODphwRA7lm88bGKY8b7tWOtepyEvaLxMI7GZF5ScwpZTYeEDNUKPzvM2Im9zehIaznpguNdNXNMLWnwPu4H6zEvajkw3G3ucSiXKmh6XNe3hkdSANm3vnxzRXm4fcuzAx68IElXE2bkGFElluDLo6EsUDWZ4JIWBVaDwYdJx8uCXbQdoifzCs5kuuClaDaDqIhb5hJ2WR8mxiueFsS0aDGdIYmye5svmNmzQxFmdOkHoF7CfwuU1yy4uEEt9vPSP2wFp1dyaMvJW68vtB4kddLmI6gIgVVcT6ZX1Qm6WsusPrdisPLB2ScodXojCbL3DLj6PKG8QDVMWTrL1TpafT2wslRledWIhsTlv2mI3C066WMcTSwKLXdEDhVvFJ6ShiLKSN7gnRrlE0BnAw", C8.pack "saltKEYbcTcXHCBxtjD2PnBh44AIQ6XUOCESOhXpEp3HrcGMwbjzQKMSaf63IJemkURWoqHusIeVB8Il91NjiCGQacPUu9qTFaShLbKG0Yj4RCMV56WPj7E14EMpbxy6PlBdILBOkKUB6TGTPJXh1tpdOHTG6KuIvcbQp9qWjaf1uxAKgiTtYRIHhxjJI2viVa6fDZ67QOouOaf2RXQhpsWaTtAVnff6PIFcvJhdPDFGV5nvmZWoCZQodj6yXRDHPw9PyF0iLYm9uFtEunlAAxGB5qqea4X5tZvB1OfLVwymY3a3JPjdxTdvHxCHbqqE0zip61JNqdmeWxGtlRBC6CGoCiHO4XxHCntQBRJDcG0zW7joTdgtTBarsQQhlLXBGMNBSNmmTbDf3hFtawUBCJH18IAiRMwyeQJbJ2bERsY3MVRPuYCf4Au7gN72iGh1lRktSQtEFye7pO46kMXRrEjHQWXInMzzy7X2StXUzHVTFF2VdOoKn0WUqFNvB6PF7qIsOlYKj57bi1Psa34s85WxMSbTkhrd7VHdHZkTVaWdraohXYOePdeEvIwObCGEXkETUzqM5P2yzoBOJSdjpIYaa8zzdLD3yrb1TwCZuJVxsrq0XXY6vErU4QntsW0972XmGNyumFNJiPm4ONKh1RLvS1kddY3nm8276S4TUuZfrRQO8QxZRNuSaZI8JRZp5VojB5DktuMxAQkqoPjQ5Vtb6oXeOyY591CB1MEW1fLTCs0NrL321SaNRMqza1ETogAxpEiYwZ6pIgnMmSqNMRdZnCqA4gMWw1lIVATWK83OCeicNRUNOdfzS7A8vbLcmvKPtpOFvhNzwrrUdkvuKvaYJviQgeR7snGetO9JLCwIlHIj52gMCNU18d32SJl7Xomtl3wIe02SMvq1i1BcaX7lXioqWGmgVqBWU3fsUuGwHi6RUKCCQdEOBfNo2WdpFaCflcgnn0O6jVHCqkv8cQk81AqS00rAmHGCNTwyA6Tq5TXoLlDnC8gAQjDUsZp0z", 1, 65, C8.pack "384BCD6914407E40C295D1037CF4F990E8F0E720AF43CB706683177016D36D1A14B3A7CF22B5DF8D5D7D44D69610B64251ADE2E7AB54A3813A89935592E391BF91"), 
  
  (C8.pack "passDATA", C8.pack "saltKEYbc", 16777216, 7, C8.pack "AB96C76400D08B"), 
  (C8.pack "passDATAb00AB", C8.pack "saltKEYbcTcX", 2097152, 481, C8.pack "C8CB4B4B498B32CDE191159866A8E86B4C9D84EF1D0A37CF7B9BDC7872EDD5F02242AA7D83172C778EF64C788D622ACBCD4317C4B63A2EDE184CB2A5F6B94815C395CC822D68C637ADB0E928C9692D32D6B66B3825CDB6AC9B57D9D15BCA72CC32773CA45350BB460F83172B75EDD418E2C39DF437FFFDDEF6FF5E83AFC2974E5B391303C80B73DA815E979118FB41ACC3E2019DB30C14650DC7E75D67A048541563A3ECA996CF15F9B3DD7C768B45613078CF772292F092CCFEC10F027669D60EDF56A383894F0EFD7DDC3551E1C6AA366F7EFB39981BF0BDF7894A83D051E900AF2FB81CA990F52EE613A5C2D28D28683E331F50BD10B6F8AF12705E505BCA3BB0D3869246863387DD385748718B3AAA51BA12BB067F1ABD6B8F2E0DECDA0A6693D1331349470E78212B2B4700709BC22C86AE7ADAB9C74635BC0E40A18BE604B8BE7ED1E0419258BB0C38D27264783FE2A915CD63C7CBB6C2D937803D86FFE9DC58132F2AF7642C782AF6A0D50AB47622A73EF16618E15B5CE8EEE9F5A1A477A02ADB5E95638792811013A9A8ACC9F618C4726DC26E67C1DDCE6E1E90594C94D4DE8FD8D89400AB3E8138089B4CD5893BD66691708D1C27FF7E69F12D1A15983352933DE1583A2127DC8B62E345C0B1CD14F9F7BC85FFBCEB40E80E84E8E8C0")]

toUpper = C8.map toUpper'
  where 
    toUpper' 'a' = 'A'
    toUpper' 'b' = 'B'
    toUpper' 'c' = 'C'
    toUpper' 'd' = 'D'
    toUpper' 'e' = 'E'
    toUpper' 'f' = 'F'
    toUpper' x = x

prop_testHmacSha512Pbkdf test = toUpper generated == result
  where
    generated = B16.encode $ C8.take len $ hmacSha512Pbkdf2 pass salt iter
    (pass, salt, iter, len, result) = test

countIf :: (a -> Bool) -> [a] -> Int
countIf cond = Prelude.length . Prelude.filter cond

evalPrint :: [Bool] -> IO ()
evalPrint x = evalPrint' x 1 $ Prelude.length x
  where
  evalPrint' [] _ _ = Prelude.putStrLn "\nDone"
  evalPrint' (x:xs) current total = do
      seq x Prelude.putStr $ "\r" ++ (show current) ++ "/" ++ (show total) ++ " performed"
      evalPrint' xs (current + 1) total

main = do
  hSetBuffering stdout NoBuffering
  evalPrint results
  Prelude.putStrLn $ (show successful) ++ " successful and " ++ (show failed) ++ " failed"
  exit
  where
    successful = countIf (\x -> x) results
    failed = countIf (\x -> not x) results
    results = Prelude.map (\x -> prop_testHmacSha512Pbkdf x) test_vectors
    exit
      | failed == 0 = exitSuccess
      | otherwise = exitFailure
