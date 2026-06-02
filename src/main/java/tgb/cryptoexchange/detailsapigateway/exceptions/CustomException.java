package tgb.cryptoexchange.detailsapigateway.exceptions;

import com.google.rpc.Code;

public interface CustomException {

    Code getErrorCode();

    String getField();

    String getDescription();

}
