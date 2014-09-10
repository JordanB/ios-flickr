//
// Flickr.m
//
// Copyright (c) 2014 Jordan Bonnet
//
// Permission is hereby granted, free of charge, to any person
// obtaining a copy of this software and associated documentation
// files (the "Software"), to deal in the Software without
// restriction, including without limitation the rights to use,
// copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following
// conditions:
//
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
// OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
// HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
// WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
// OTHER DEALINGS IN THE SOFTWARE.
//

#import "Flickr.h"
#import "AFHTTPRequestOperationManager.h"
#import <CommonCrypto/CommonDigest.h>
#import <Foundation/Foundation.h>

#pragma mark Helpers

NSString *md5HexStringFromNSString(NSString *inStr)
{
    const char *data = [inStr UTF8String];
    CC_LONG length = (CC_LONG) strlen(data);
    
    unsigned char *md5buf = (unsigned char*)calloc(1, CC_MD5_DIGEST_LENGTH);
    
    CC_MD5_CTX md5ctx;
    CC_MD5_Init(&md5ctx);
    CC_MD5_Update(&md5ctx, data, length);
    CC_MD5_Final(md5buf, &md5ctx);
    
    NSMutableString *md5hex = [NSMutableString string];
	size_t i;
    for (i = 0 ; i < CC_MD5_DIGEST_LENGTH ; i++) {
        [md5hex appendFormat:@"%02x", md5buf[i]];
    }
    free(md5buf);
    return md5hex;
}

NSString *escapedURLStringFromNSStringWithExtraEscapedChars(NSString *inStr, NSString *inEscChars)
{
	CFStringRef escaped = CFURLCreateStringByAddingPercentEscapes(NULL, (CFStringRef)inStr, NULL, (CFStringRef)inEscChars, kCFStringEncodingUTF8);
    
#if MAC_OS_X_VERSION_MAX_ALLOWED <= MAC_OS_X_VERSION_10_4
	return (NSString *)[(NSString*)escaped autorelease];
#else
	return (NSString *)CFBridgingRelease(escaped);
#endif
}

NSString *escapedURLStringFromNSString(NSString *inStr)
{
	return escapedURLStringFromNSStringWithExtraEscapedChars(inStr, @"&");
}

NSString *generateUUIDString(void)
{
    CFUUIDRef uuid = CFUUIDCreate(NULL);
    CFStringRef uuidStr = CFUUIDCreateString(NULL, uuid);
    CFRelease(uuid);
    
#if MAC_OS_X_VERSION_MAX_ALLOWED <= MAC_OS_X_VERSION_10_4
	return (NSString *)[(NSString*)uuidStr autorelease];
#else
	return (NSString *)CFBridgingRelease(uuidStr);
#endif
}

static NSData *sha1(NSData *inData)
{
    NSMutableData *result = [NSMutableData dataWithLength:CC_SHA1_DIGEST_LENGTH];
    CC_SHA1_CTX context;
    CC_SHA1_Init(&context);
    CC_SHA1_Update(&context, [inData bytes], (CC_LONG)[inData length]);
    CC_SHA1_Final([result mutableBytes], &context);
    return result;
}

static char *NewBase64Encode(const void *buffer, size_t length, bool separateLines, size_t *outputLength);

NSString *HMACSha1Base64(NSString *inKey, NSString *inMessage)
{
    NSData *keyData = [inKey dataUsingEncoding:NSUTF8StringEncoding];
    
    if ([keyData length] > CC_SHA1_BLOCK_BYTES) {
        keyData = sha1(keyData);
    }
    
    if ([keyData length] < CC_SHA1_BLOCK_BYTES) {
        NSUInteger padSize = CC_SHA1_BLOCK_BYTES - [keyData length];
        
        NSMutableData *paddedData = [NSMutableData dataWithData:keyData];
        [paddedData appendData:[NSMutableData dataWithLength:padSize]];
        keyData  = paddedData;
    }
    
    NSMutableData *oKeyPad = [NSMutableData dataWithLength:CC_SHA1_BLOCK_BYTES];
    NSMutableData *iKeyPad = [NSMutableData dataWithLength:CC_SHA1_BLOCK_BYTES];
    
    const uint8_t *kdPtr = [keyData bytes];
    uint8_t *okpPtr = [oKeyPad mutableBytes];
    uint8_t *ikpPtr = [iKeyPad mutableBytes];
    
    memset(okpPtr, 0x5c, CC_SHA1_BLOCK_BYTES);
    memset(ikpPtr, 0x36, CC_SHA1_BLOCK_BYTES);
    
    NSUInteger i;
    for (i = 0; i < CC_SHA1_BLOCK_BYTES; i++) {
        okpPtr[i] = okpPtr[i] ^ kdPtr[i];
        ikpPtr[i] = ikpPtr[i] ^ kdPtr[i];
    }
    
    NSData *msgData = [inMessage dataUsingEncoding:NSUTF8StringEncoding];
    
    NSMutableData *innerData = [NSMutableData dataWithData:iKeyPad];
    [innerData appendData:msgData];
    NSData *innerDataHashed = sha1(innerData);
    
    NSMutableData *outerData = [NSMutableData dataWithData:oKeyPad];
    [outerData appendData:innerDataHashed];
    
    NSData *outerHashedData = sha1(outerData);
    
    
	size_t outputLength;
	char *outputBuffer = NewBase64Encode([outerHashedData bytes], [outerHashedData length], true, &outputLength);
	
	NSString *result = [[NSString alloc] initWithBytes:outputBuffer length:outputLength encoding:NSASCIIStringEncoding];
	free(outputBuffer);
	return result;
}

NSDictionary *extractURLQueryParameter(NSString *inQuery)
{
    if (![inQuery length]) {
        return nil;
    }
    
    NSArray *params = [inQuery componentsSeparatedByString:@"&"];
    
    NSMutableDictionary *dict = [NSMutableDictionary dictionary];
    for (NSString *p in params) {
        NSArray *kv = [p componentsSeparatedByString:@"="];
        if ([kv count] != 2) {
            return nil;
        }
        
        [dict setObject:[kv objectAtIndex:1] forKey:[kv objectAtIndex:0]];
    }
    return dict;
}

static unsigned char base64EncodeLookup[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

#define BINARY_UNIT_SIZE 3
#define BASE64_UNIT_SIZE 4

static char *NewBase64Encode(
                             const void *buffer,
                             size_t length,
                             bool separateLines,
                             size_t *outputLength)
{
	const unsigned char *inputBuffer = (const unsigned char *)buffer;
	
#define MAX_NUM_PADDING_CHARS 2
#define OUTPUT_LINE_LENGTH 64
#define INPUT_LINE_LENGTH ((OUTPUT_LINE_LENGTH / BASE64_UNIT_SIZE) * BINARY_UNIT_SIZE)
#define CR_LF_SIZE 2
	
	//
	// Byte accurate calculation of final buffer size
	//
	size_t outputBufferSize =
    ((length / BINARY_UNIT_SIZE)
     + ((length % BINARY_UNIT_SIZE) ? 1 : 0))
    * BASE64_UNIT_SIZE;
	if (separateLines)
	{
		outputBufferSize +=
        (outputBufferSize / OUTPUT_LINE_LENGTH) * CR_LF_SIZE;
	}
	
	//
	// Include space for a terminating zero
	//
	outputBufferSize += 1;
    
	//
	// Allocate the output buffer
	//
	char *outputBuffer = (char *)malloc(outputBufferSize);
	if (!outputBuffer)
	{
		return NULL;
	}
    
	size_t i = 0;
	size_t j = 0;
	const size_t lineLength = separateLines ? INPUT_LINE_LENGTH : length;
	size_t lineEnd = lineLength;
	
	while (true)
	{
		if (lineEnd > length)
		{
			lineEnd = length;
		}
        
		for (; i + BINARY_UNIT_SIZE - 1 < lineEnd; i += BINARY_UNIT_SIZE)
		{
			//
			// Inner loop: turn 48 bytes into 64 base64 characters
			//
			outputBuffer[j++] = base64EncodeLookup[(inputBuffer[i] & 0xFC) >> 2];
			outputBuffer[j++] = base64EncodeLookup[((inputBuffer[i] & 0x03) << 4)
                                                   | ((inputBuffer[i + 1] & 0xF0) >> 4)];
			outputBuffer[j++] = base64EncodeLookup[((inputBuffer[i + 1] & 0x0F) << 2)
                                                   | ((inputBuffer[i + 2] & 0xC0) >> 6)];
			outputBuffer[j++] = base64EncodeLookup[inputBuffer[i + 2] & 0x3F];
		}
		
		if (lineEnd == length)
		{
			break;
		}
		
		//
		// Add the newline
		//
		outputBuffer[j++] = '\r';
		outputBuffer[j++] = '\n';
		lineEnd += lineLength;
	}
	
	if (i + 1 < length)
	{
		//
		// Handle the single '=' case
		//
		outputBuffer[j++] = base64EncodeLookup[(inputBuffer[i] & 0xFC) >> 2];
		outputBuffer[j++] = base64EncodeLookup[((inputBuffer[i] & 0x03) << 4)
                                               | ((inputBuffer[i + 1] & 0xF0) >> 4)];
		outputBuffer[j++] = base64EncodeLookup[(inputBuffer[i + 1] & 0x0F) << 2];
		outputBuffer[j++] =	'=';
	}
	else if (i < length)
	{
		//
		// Handle the double '=' case
		//
		outputBuffer[j++] = base64EncodeLookup[(inputBuffer[i] & 0xFC) >> 2];
		outputBuffer[j++] = base64EncodeLookup[(inputBuffer[i] & 0x03) << 4];
		outputBuffer[j++] = '=';
		outputBuffer[j++] = '=';
	}
	outputBuffer[j] = 0;
	
	//
	// Set the output length and return the buffer
	//
	if (outputLength)
	{
		*outputLength = j;
	}
	return outputBuffer;
}

#pragma mark Flickr

// permisions
NSString *const FlickrReadPermission = @"read";
NSString *const FlickrWritePermission = @"write";
NSString *const FlickrDeletePermission = @"delete";

// urls
static NSString *const kFlickrURLOAuth = @"https://www.flickr.com/services/oauth/";
static NSString *const kFlickrURLAPI = @"https://api.flickr.com/services/rest/";

// utils
static NSString *const kEscapeChars = @"`~!@#$^&*()=+[]\\{}|;':\",/<>?";

@implementation Flickr
{
    NSOperationQueue *_operationQueue;
}

#pragma mark Public methods

- (id)initWithAPIKey:(NSString *)apiKey sharedSecret:(NSString *)sharedSecret
{
    if ((self = [super init])) {
        _key = [apiKey copy];
        _sharedSecret = [sharedSecret copy];
        _operationQueue = [[NSOperationQueue alloc] init];
    }
    return self;
}

- (NSURL *)userAuthorizationURLWithRequestToken:(NSString *)requestToken
                            requestedPermission:(NSString *)permission
{
    NSMutableString *urlString = [NSMutableString stringWithFormat:@"%@%@", kFlickrURLOAuth, @"authorize"];
    [urlString appendFormat:@"?%@=%@", @"oauth_token", requestToken];
    if (permission.length > 0) {
        [urlString appendFormat:@"&%@=%@", @"perms", permission];
    }
    return [NSURL URLWithString:urlString];
}

- (void)fetchRequestTokenWithCallbackURL:(NSURL *)callbackURL
                                 success:(void (^)(NSString *requestToken))success
                                 failure:(void (^)(NSInteger statusCode, NSError *error))failure
{
    _oauthToken = nil;
    _oauthTokenSecret = nil;

    NSString *urlString = [NSString stringWithFormat:@"%@%@", kFlickrURLOAuth, @"request_token"];
    NSURL *requestURL = [self _oauthURLFromBaseURL:[NSURL URLWithString:urlString]
                                            method:@"GET"
                                         arguments:@{@"oauth_callback": [callbackURL absoluteString]}];

    AFHTTPRequestOperation *requestOperation = [[AFHTTPRequestOperation alloc] initWithRequest:[NSURLRequest requestWithURL:requestURL]];
    requestOperation.responseSerializer = [AFHTTPResponseSerializer serializer];
    [requestOperation setCompletionBlockWithSuccess:^(AFHTTPRequestOperation *operation, id responseObject) {
        if (success) {
            NSString *responseString = [[NSString alloc] initWithData:responseObject encoding:NSUTF8StringEncoding];
            NSDictionary *responseDictionary = extractURLQueryParameter(responseString);
            _oauthToken = responseDictionary[@"oauth_token"];
            _oauthTokenSecret = responseDictionary[@"oauth_token_secret"];
            success(_oauthToken);
        }
    } failure:^(AFHTTPRequestOperation *operation, NSError *error) {
        if (failure) {
            failure(operation.response.statusCode, error);
        }
    }];
    [_operationQueue addOperation:requestOperation];
}

- (void)fetchAccessTokenWithRequestToken:(NSString *)requestToken
                                verifier:(NSString *)verifier
                                 success:(void (^)())success
                                 failure:(void (^)(NSInteger statusCode, NSError *error))failure
{
    NSString *urlString = [NSString stringWithFormat:@"%@%@", kFlickrURLOAuth, @"access_token"];
    NSURL *requestURL = [self _oauthURLFromBaseURL:[NSURL URLWithString:urlString]
                                            method:@"GET"
                                         arguments:@{@"oauth_token": requestToken, @"oauth_verifier": verifier}];

    AFHTTPRequestOperation *requestOperation = [[AFHTTPRequestOperation alloc] initWithRequest:[NSURLRequest requestWithURL:requestURL]];
    requestOperation.responseSerializer = [AFHTTPResponseSerializer serializer];
    [requestOperation setCompletionBlockWithSuccess:^(AFHTTPRequestOperation *operation, id responseObject) {
        if (success) {
            NSString *responseString = [[NSString alloc] initWithData:responseObject encoding:NSUTF8StringEncoding];
            NSDictionary *responseDictionary = extractURLQueryParameter(responseString);
            _oauthToken = responseDictionary[@"oauth_token"];
            _oauthTokenSecret = responseDictionary[@"oauth_token_secret"];
            _username = [responseDictionary[@"username"] stringByReplacingPercentEscapesUsingEncoding:NSUTF8StringEncoding];
            _fullname = [responseDictionary[@"fullname"] stringByReplacingPercentEscapesUsingEncoding:NSUTF8StringEncoding];
            _userId = [responseDictionary[@"user_nsid"] stringByReplacingPercentEscapesUsingEncoding:NSUTF8StringEncoding];
            success();
        }
    } failure:^(AFHTTPRequestOperation *operation, NSError *error) {
        if (failure) {
            failure(operation.response.statusCode, error);
        }
    }];
    [_operationQueue addOperation:requestOperation];
}

- (void)sendWithMethod:(NSString *)method
                  path:(NSString *)path
             arguments:(NSDictionary *)arguments
               success:(void (^)(NSDictionary *responseDictionary))success
               failure:(void (^)(NSInteger statusCode, NSError *error))failure
{
	NSMutableDictionary *parameters = [NSMutableDictionary dictionary];
    [parameters setObject:path forKey:@"method"];
    [parameters setObject:@"json" forKey:@"format"];
    [parameters setObject:@"1" forKey:@"nojsoncallback"];

    if (arguments) {
        [parameters addEntriesFromDictionary:arguments];
    }

    NSURL *requestURL = [self _oauthURLFromBaseURL:[NSURL URLWithString:kFlickrURLAPI]
                                            method:method
                                         arguments:parameters];

    AFHTTPRequestOperation *requestOperation = [[AFHTTPRequestOperation alloc] initWithRequest:[NSURLRequest requestWithURL:requestURL]];
    requestOperation.responseSerializer = [AFJSONResponseSerializer serializer];
    [requestOperation setCompletionBlockWithSuccess:^(AFHTTPRequestOperation *operation, id responseObject) {
        if (success) {
            success((NSDictionary *)responseObject);
        }
    } failure:^(AFHTTPRequestOperation *operation, NSError *error) {
        if (failure) {
            failure(operation.response.statusCode, error);
        }
    }];
    [_operationQueue addOperation:requestOperation];
}

- (void)signOut
{
    [_operationQueue cancelAllOperations];
    _oauthToken = nil;
    _oauthTokenSecret = nil;
    _username = nil;
    _fullname = nil;
    _userId = nil;
}

#pragma mark Private methods

- (NSURL *)_oauthURLFromBaseURL:(NSURL *)url method:(NSString *)method arguments:(NSDictionary *)arguments
{
    NSDictionary *newArgs = [self _signedOAuthHTTPQueryArguments:arguments baseURL:url method:method];

    NSMutableArray *queryArray = [NSMutableArray array];
    NSEnumerator *kenum = [newArgs keyEnumerator];
    NSString *k;
    while ((k = [kenum nextObject]) != nil) {
        [queryArray addObject:[NSString stringWithFormat:@"%@=%@", k, escapedURLStringFromNSStringWithExtraEscapedChars([[newArgs objectForKey:k] description], kEscapeChars)]];
    }

    NSString *newURLStringWithQuery = [NSString stringWithFormat:@"%@?%@", [url absoluteString], [queryArray componentsJoinedByString:@"&"]];
    return [NSURL URLWithString:newURLStringWithQuery];
}

- (NSDictionary *)_signedOAuthHTTPQueryArguments:(NSDictionary *)arguments baseURL:(NSURL *)url method:(NSString *)method
{
    NSMutableDictionary *newArgs = [NSMutableDictionary dictionaryWithDictionary:arguments];
    [newArgs setObject:[generateUUIDString() substringToIndex:8] forKey:@"oauth_nonce"];
    [newArgs setObject:[NSString stringWithFormat:@"%lu", (long)[[NSDate date] timeIntervalSince1970]] forKey:@"oauth_timestamp"];
    [newArgs setObject:@"1.0" forKey:@"oauth_version"];
    [newArgs setObject:@"HMAC-SHA1" forKey:@"oauth_signature_method"];
    [newArgs setObject:_key forKey:@"oauth_consumer_key"];

    if (![arguments objectForKey:@"oauth_token"] && _oauthToken) {
        [newArgs setObject:_oauthToken forKey:@"oauth_token"];
    }

    NSString *signatureKey = [NSString stringWithFormat:@"%@&%@", _sharedSecret, _oauthTokenSecret ? _oauthTokenSecret : @""];

    NSMutableString *baseString = [NSMutableString string];
    [baseString appendString:method];
    [baseString appendString:@"&"];
    [baseString appendString:escapedURLStringFromNSStringWithExtraEscapedChars([url absoluteString], kEscapeChars)];

    NSArray *sortedArgKeys = [[newArgs allKeys] sortedArrayUsingSelector:@selector(compare:)];
    [baseString appendString:@"&"];

    NSMutableArray *baseStrArgs = [NSMutableArray array];
    NSEnumerator *kenum = [sortedArgKeys objectEnumerator];
    NSString *k;
    while ((k = [kenum nextObject]) != nil) {
        [baseStrArgs addObject:[NSString stringWithFormat:@"%@=%@", k, escapedURLStringFromNSStringWithExtraEscapedChars([[newArgs objectForKey:k] description], kEscapeChars)]];
    }
    [baseString appendString:escapedURLStringFromNSStringWithExtraEscapedChars([baseStrArgs componentsJoinedByString:@"&"], kEscapeChars)];

    NSString *signature = HMACSha1Base64(signatureKey, baseString);
    [newArgs setObject:signature forKey:@"oauth_signature"];
    return newArgs;
}

@end