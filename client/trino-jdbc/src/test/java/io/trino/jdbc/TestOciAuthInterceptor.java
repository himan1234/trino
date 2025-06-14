package io.trino.jdbc;

import com.oracle.bmc.auth.AuthenticationDetailsProvider;
import com.oracle.bmc.http.signing.RequestSigner;
import okhttp3.HttpUrl;
import okhttp3.Interceptor;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.MockitoAnnotations.openMocks;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;

public class TestOciAuthInterceptor
{
    @Mock
    private RequestSigner mockRequestSigner;
    @Mock
    private AuthenticationDetailsProvider mockAuthProvider;
    @Mock
    private Interceptor.Chain mockChain;

    @Captor
    private ArgumentCaptor<Request> requestCaptor;
    @Captor
    private ArgumentCaptor<Map<String, List<String>>> headersCaptor;
    @Captor
    private ArgumentCaptor<URI> uriCaptor;
    @Captor
    private ArgumentCaptor<String> methodCaptor;
    @Captor
    private ArgumentCaptor<InputStream> bodyCaptor;

    private TrinoConnection.OciAuthInterceptor ociAuthInterceptor;

    @BeforeMethod
    public void setup()
    {
        openMocks(this);
        ociAuthInterceptor = new TrinoConnection.OciAuthInterceptor(mockRequestSigner, mockAuthProvider);

        // Mock the chain to return a dummy response
        Request dummyRequest = new Request.Builder().url("http://localhost/test").build();
        Response dummyResponse = new Response.Builder()
                .request(dummyRequest)
                .protocol(okhttp3.Protocol.HTTP_1_1)
                .code(200)
                .message("OK")
                .body(ResponseBody.create("", MediaType.parse("application/json")))
                .build();
        try {
            when(mockChain.request()).thenReturn(dummyRequest);
            when(mockChain.proceed(any(Request.class))).thenReturn(dummyResponse);
        } catch (IOException e) {
            throw new RuntimeException(e); // Should not happen in mock setup
        }
    }

    @Test
    public void testInterceptorSignsRequestAndAddsHeaders() throws IOException
    {
        HttpUrl url = HttpUrl.parse("http://example.com/query");
        Request originalRequest = new Request.Builder()
                .url(url)
                .header("X-Custom-Header", "CustomValue")
                .post(RequestBody.create("test body", MediaType.parse("text/plain")))
                .build();

        when(mockChain.request()).thenReturn(originalRequest);

        Map<String, String> signedHeaders = new HashMap<>();
        signedHeaders.put("Authorization", "OCI Signature");
        signedHeaders.put("date", "some-date");
        signedHeaders.put("host", "example.com");
        when(mockRequestSigner.signRequest(any(URI.class), any(String.class), any(Map.class), any(InputStream.class)))
                .thenReturn(signedHeaders);

        ociAuthInterceptor.intercept(mockChain);

        verify(mockRequestSigner).signRequest(uriCaptor.capture(), methodCaptor.capture(), headersCaptor.capture(), bodyCaptor.capture());
        verify(mockChain).proceed(requestCaptor.capture());

        Request signedRequest = requestCaptor.getValue();

        assertEquals(uriCaptor.getValue(), originalRequest.url().uri());
        assertEquals(methodCaptor.getValue(), originalRequest.method());

        Map<String, List<String>> capturedHeadersForSigning = headersCaptor.getValue();
        assertTrue(capturedHeadersForSigning.containsKey("X-Custom-Header"));
        assertEquals(capturedHeadersForSigning.get("X-Custom-Header").get(0), "CustomValue");
        assertTrue(capturedHeadersForSigning.containsKey("host")); // host header should be added if not present
        assertEquals(capturedHeadersForSigning.get("host").get(0), "example.com");


        assertNotNull(bodyCaptor.getValue(), "Body input stream should not be null for POST requests");

        assertEquals(signedRequest.header("Authorization"), "OCI Signature");
        assertEquals(signedRequest.header("date"), "some-date");
        // The host header might be set by OkHttp itself, but the interceptor ensures it's available for signing.
        // The signedRequest will have the host header as set by OkHttp or by the interceptor if added for signing.
        assertNotNull(signedRequest.header("host"));
        assertEquals(signedRequest.header("X-Custom-Header"), "CustomValue"); // Original header should persist
    }

    @Test
    public void testInterceptorHandlesGetRequest() throws IOException
    {
        HttpUrl url = HttpUrl.parse("http://example.com/get_query");
        Request originalRequest = new Request.Builder()
                .url(url)
                .get()
                .build();

        when(mockChain.request()).thenReturn(originalRequest);

        Map<String, String> signedHeadersFromSigner = new HashMap<>();
        signedHeadersFromSigner.put("Authorization", "OCI GET Signature");
        signedHeadersFromSigner.put("date", "get-date");
        when(mockRequestSigner.signRequest(any(URI.class), any(String.class), any(Map.class), any()))
                .thenReturn(signedHeadersFromSigner); // Allow null for body InputStream

        ociAuthInterceptor.intercept(mockChain);

        verify(mockRequestSigner).signRequest(uriCaptor.capture(), methodCaptor.capture(), headersCaptor.capture(), bodyCaptor.capture());
        verify(mockChain).proceed(requestCaptor.capture());

        Request signedRequest = requestCaptor.getValue();

        assertEquals(uriCaptor.getValue(), originalRequest.url().uri());
        assertEquals(methodCaptor.getValue(), "GET");
        assertTrue(headersCaptor.getValue().containsKey("host")); // host header
        assertEquals(headersCaptor.getValue().get("host").get(0), "example.com");

        // For GET request, bodyCaptor.getValue() might be null or an empty stream depending on OkHttp/OCI SDK.
        // The key is that signRequest is called correctly.

        assertEquals(signedRequest.header("Authorization"), "OCI GET Signature");
        assertEquals(signedRequest.header("date"), "get-date");
    }
}
