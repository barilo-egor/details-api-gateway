package tgb.cryptoexchange.detailsapigateway.exceptions;

import com.google.rpc.Code;
import lombok.Getter;

import static com.google.rpc.Code.INTERNAL;

@Getter
public class BaseException extends RuntimeException implements CustomException {

    private final Code errorCode;

    private final String field;

    private final String description;

    public BaseException(String message) {
        super(message);
        this.errorCode = INTERNAL;
        this.field = null;
        this.description = null;
    }

}
