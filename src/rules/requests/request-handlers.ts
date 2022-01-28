import _ = require('lodash');
import net = require('net');
import { encode as encodeBase64, decode as decodeBase64 } from 'base64-arraybuffer';
import { Readable, Transform } from 'stream';
import { stripIndent, oneLine } from 'common-tags';
import { TypedError } from 'typed-error';

import {
    Headers,
    OngoingRequest,
    CompletedRequest,
    OngoingResponse,
    Explainable,
} from "../../types";

import { MaybePromise, Replace } from '../../util/type-utils';
import { readFile } from '../../util/fs';
import {
    waitForCompletedRequest,
    setHeaders,
    buildBodyReader,
    dropDefaultHeaders,
} from '../../util/request-utils';
import {
    Serializable,
    ClientServerChannel,
    withSerializedBodyReader,
    withDeserializedBodyReader,
    withSerializedBodyBuffer,
    withDeserializedBodyBuffer,
    WithSerializedBodyBuffer,
} from "../../util/serialization";

import PassThroughHandler from './PassThroughHandler';
export * from './PassThroughHandler';

// An error that indicates that the handler is aborting the request.
// This could be intentional, or an upstream server aborting the request.
export class AbortError extends TypedError { }

export type SerializedBuffer = { type: 'Buffer', data: number[] };

export interface CallbackRequestResult {
    method?: string;
    url?: string;
    headers?: Headers;

    json?: any;
    body?: string | Buffer;

    response?: CallbackResponseResult;
}

export type CallbackResponseResult =
    | CallbackResponseMessageResult
    | 'close';

export interface CallbackResponseMessageResult {
    statusCode?: number;
    status?: number; // exists for backwards compatibility only
    statusMessage?: string;
    headers?: Headers;

    json?: any;
    body?: string | Buffer | Uint8Array;
}

function isSerializedBuffer(obj: any): obj is SerializedBuffer {
    return obj && obj.type === 'Buffer' && !!obj.data;
}

export interface RequestHandler extends Explainable, Serializable {
    type: keyof typeof HandlerLookup;
    handle(request: OngoingRequest, response: OngoingResponse): Promise<void>;
}

export class SimpleHandler extends Serializable implements RequestHandler {
    readonly type = 'simple';

    constructor(
        public status: number,
        public statusMessage?: string,
        public data?: string | Uint8Array | Buffer | SerializedBuffer,
        public headers?: Headers
    ) {
        super();

        validateCustomHeaders({}, headers);
    }

    explain() {
        return `respond with status ${this.status}` +
            (this.statusMessage ? ` (${this.statusMessage})` : "") +
            (this.headers ? `, headers ${JSON.stringify(this.headers)}` : "") +
            (this.data ? ` and body "${this.data}"` : "");
    }

    async handle(_request: OngoingRequest, response: OngoingResponse) {
        if (this.headers) {
            dropDefaultHeaders(response);
            setHeaders(response, this.headers);
        }
        response.writeHead(this.status, this.statusMessage);

        if (isSerializedBuffer(this.data)) {
            this.data = Buffer.from(<any>this.data);
        }

        response.end(this.data || "");
    }
}

export interface SerializedCallbackHandlerData {
    type: string;
    name?: string;
    version?: number;
}

interface CallbackRequestMessage {
    args: [
        | Replace<CompletedRequest, 'body', string> // New format
        | CompletedRequest // Old format with directly serialized body
    ];
}

export function writeResponseFromCallback(result: CallbackResponseMessageResult, response: OngoingResponse) {
    if (result.json !== undefined) {
        result.headers = _.assign(result.headers || {}, { 'Content-Type': 'application/json' });
        result.body = JSON.stringify(result.json);
        delete result.json;
    }

    if (result.headers) {
        dropDefaultHeaders(response);
        validateCustomHeaders({}, result.headers);
        setHeaders(response, dropUndefinedValues(result.headers));
    }

    response.writeHead(
        result.statusCode || result.status || 200,
        result.statusMessage
    );
    response.end(result.body || "");
}

export class CallbackHandler extends Serializable implements RequestHandler {
    readonly type = 'callback';

    constructor(
        public callback: (request: CompletedRequest) => MaybePromise<CallbackResponseResult>
    ) {
        super();
    }

    explain() {
        return 'respond using provided callback' + (this.callback.name ? ` (${this.callback.name})` : '');
    }

    async handle(request: OngoingRequest, response: OngoingResponse) {
        let req = await waitForCompletedRequest(request);

        let outResponse: CallbackResponseResult;
        try {
            outResponse = await this.callback(req);
        } catch (error) {
            response.writeHead(500, 'Callback handler threw an exception');
            response.end(error.toString());
            return;
        }

        if (outResponse === 'close') {
            (request as any).socket.end();
            throw new AbortError('Connection closed (intentionally)');
        } else {
            writeResponseFromCallback(outResponse, response);
        }
    }

    /**
     * @internal
     */
    serialize(channel: ClientServerChannel): SerializedCallbackHandlerData {
        channel.onRequest<
            CallbackRequestMessage,
            CallbackResponseResult
        >(async (streamMsg) => {
            const request = _.isString(streamMsg.args[0].body)
                ? withDeserializedBodyReader( // New format: body serialized as base64
                    streamMsg.args[0] as Replace<CompletedRequest, 'body', string>
                )
                : { // Backward compat: old fully-serialized format
                    ...streamMsg.args[0],
                    body: buildBodyReader(streamMsg.args[0].body.buffer, streamMsg.args[0].headers)
                };

            const callbackResult = await this.callback.call(null, request);

            if (typeof callbackResult === 'string') {
                return callbackResult;
            } else {
                return withSerializedBodyBuffer(callbackResult);
            }
        });

        return { type: this.type, name: this.callback.name, version: 2 };
    }

    /**
     * @internal
     */
    static deserialize({ name, version }: SerializedCallbackHandlerData, channel: ClientServerChannel): CallbackHandler {
        const rpcCallback = async (request: CompletedRequest) => {
            const callbackResult = await channel.request<
                CallbackRequestMessage,
                WithSerializedBodyBuffer<CallbackResponseMessageResult> | 'close'
            >({
                args: [
                    (version || -1) >= 2
                        ? withSerializedBodyReader(request)
                        : request // Backward compat: old handlers
                ]
            });

            if (typeof callbackResult === 'string') {
                return callbackResult;
            } else {
                return withDeserializedBodyBuffer(callbackResult);
            }
        };
        // Pass across the name from the real callback, for explain()
        Object.defineProperty(rpcCallback, "name", { value: name });

        // Call the client's callback (via stream), and save a handler on our end for
        // the response that comes back.
        return new CallbackHandler(rpcCallback);
    }
}

export interface SerializedStreamHandlerData {
    type: string;
    status: number;
    headers?: Headers;
};

interface StreamHandlerMessage {
    event: 'data' | 'end' | 'close' | 'error';
    content: StreamHandlerEventMessage;
}

type StreamHandlerEventMessage =
    { type: 'string', value: string } |
    { type: 'buffer', value: string } |
    { type: 'arraybuffer', value: string } |
    { type: 'nil' };

export class StreamHandler extends Serializable implements RequestHandler {
    readonly type = 'stream';

    constructor(
        public status: number,
        public stream: Readable & { done?: true },
        public headers?: Headers
    ) {
        super();

        validateCustomHeaders({}, headers);
    }

    explain() {
        return `respond with status ${this.status}` +
            (this.headers ? `, headers ${JSON.stringify(this.headers)},` : "") +
            ' and a stream of response data';
    }

    async handle(_request: OngoingRequest, response: OngoingResponse) {
        if (!this.stream.done) {
            if (this.headers) {
                dropDefaultHeaders(response);
                setHeaders(response, this.headers);
            }

            response.writeHead(this.status);
            this.stream.pipe(response);
            this.stream.done = true;
        } else {
            throw new Error(stripIndent`
                Stream request handler called more than once - this is not supported.

                Streams can typically only be read once, so all subsequent requests would be empty.
                To mock repeated stream requests, call 'thenStream' repeatedly with multiple streams.

                (Have a better way to handle this? Open an issue at ${require('../../../package.json').bugs.url})
            `);
        }
    }

    /**
     * @internal
     */
    serialize(channel: ClientServerChannel): SerializedStreamHandlerData {
        const serializationStream = new Transform({
            objectMode: true,
            transform: function (this: Transform, chunk, _encoding, callback) {
                let serializedEventData: StreamHandlerEventMessage | false =
                    _.isString(chunk) ? { type: 'string', value: chunk } :
                        _.isBuffer(chunk) ? { type: 'buffer', value: chunk.toString('base64') } :
                            (_.isArrayBuffer(chunk) || _.isTypedArray(chunk)) ? { type: 'arraybuffer', value: encodeBase64(<any>chunk) } :
                                _.isNil(chunk) && { type: 'nil' };

                if (!serializedEventData) {
                    callback(new Error(`Can't serialize streamed value: ${chunk.toString()}. Streaming must output strings, buffers or array buffers`));
                }

                callback(undefined, <StreamHandlerMessage>{
                    event: 'data',
                    content: serializedEventData
                });
            },

            flush: function (this: Transform, callback) {
                this.push(<StreamHandlerMessage>{
                    event: 'end'
                });
                callback();
            }
        });

        // When we get a ping from the server-side, pipe the real stream to serialize it and send the data across
        channel.once('data', () => {
            this.stream.pipe(serializationStream).pipe(channel, { end: false });
        });

        return { type: this.type, status: this.status, headers: this.headers };
    }

    /**
     * @internal
     */
    static deserialize(handlerData: SerializedStreamHandlerData, channel: ClientServerChannel): StreamHandler {
        const handlerStream = new Transform({
            objectMode: true,
            transform: function (this: Transform, message, encoding, callback) {
                const { event, content } = message;

                let deserializedEventData = content && (
                    content.type === 'string' ? content.value :
                        content.type === 'buffer' ? Buffer.from(content.value, 'base64') :
                            content.type === 'arraybuffer' ? Buffer.from(decodeBase64(content.value)) :
                                content.type === 'nil' && undefined
                );

                if (event === 'data' && deserializedEventData) {
                    this.push(deserializedEventData);
                } else if (event === 'end') {
                    this.end();
                }

                callback();
            }
        });

        // When we get piped (i.e. to a live request), ping upstream to start streaming, and then
        // pipe the resulting data into our live stream (which is streamed to the request, like normal)
        handlerStream.once('resume', () => {
            channel.pipe(handlerStream);
            channel.write({});
        });

        return new StreamHandler(
            handlerData.status,
            handlerStream,
            handlerData.headers
        );
    }
}

export class FileHandler extends Serializable implements RequestHandler {
    readonly type = 'file';

    constructor(
        public status: number,
        public statusMessage: string | undefined,
        public filePath: string,
        public headers?: Headers
    ) {
        super();

        validateCustomHeaders({}, headers);
    }

    explain() {
        return `respond with status ${this.status}` +
            (this.statusMessage ? ` (${this.statusMessage})` : "") +
            (this.headers ? `, headers ${JSON.stringify(this.headers)}` : "") +
            (this.filePath ? ` and body from file ${this.filePath}` : "");
    }

    async handle(_request: OngoingRequest, response: OngoingResponse) {
        // Read the file first, to ensure we error cleanly if it's unavailable
        const fileContents = await readFile(this.filePath, null);

        if (this.headers) {
            dropDefaultHeaders(response);
            setHeaders(response, this.headers);
        }

        response.writeHead(this.status, this.statusMessage);
        response.end(fileContents);
    }
}

export interface ForwardingOptions {
    targetHost: string,
    // Should the host (H1) or :authority (H2) header be updated to match?
    updateHostHeader?: true | false | string // Change automatically/ignore/change to custom value
}

// Used to drop `undefined` headers, which cause problems
export function dropUndefinedValues<D extends {}>(obj: D): D {
    return _.omitBy(obj, (v) => v === undefined) as D;
}

export function validateCustomHeaders(
    originalHeaders: Headers,
    modifiedHeaders: Headers | undefined,
    headerWhitelist: readonly string[] = []
) {
    if (!modifiedHeaders) return;

    // We ignore most returned pseudo headers, so we error if you try to manually set them
    const invalidHeaders = _(modifiedHeaders)
        .pickBy((value, name) =>
            name.toString().startsWith(':') &&
            // We allow returning a preexisting header value - that's ignored
            // silently, so that mutating & returning the provided headers is always safe.
            value !== originalHeaders[name] &&
            // In some cases, specific custom pseudoheaders may be allowed, e.g. requests
            // can have custom :scheme and :authority headers set.
            !headerWhitelist.includes(name)
        )
        .keys();

    if (invalidHeaders.size() > 0) {
        throw new Error(
            `Cannot set custom ${invalidHeaders.join(', ')} pseudoheader values`
        );
    }
}

export class CloseConnectionHandler extends Serializable implements RequestHandler {
    readonly type = 'close-connection';

    explain() {
        return 'close the connection';
    }

    async handle(request: OngoingRequest) {
        const socket: net.Socket = (<any>request).socket;
        socket.end();
        throw new AbortError('Connection closed (intentionally)');
    }
}

export class TimeoutHandler extends Serializable implements RequestHandler {
    readonly type = 'timeout';

    explain() {
        return 'time out (never respond)';
    }

    async handle() {
        // Do nothing, leaving the socket open but never sending a response.
        return new Promise<void>(() => { });
    }
}

export const HandlerLookup = {
    'simple': SimpleHandler,
    'callback': CallbackHandler,
    'stream': StreamHandler,
    'file': FileHandler,
    'passthrough': PassThroughHandler,
    'close-connection': CloseConnectionHandler,
    'timeout': TimeoutHandler
}