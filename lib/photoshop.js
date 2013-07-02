/*
 * Copyright (c) 2013 Adobe Systems Incorporated. All rights reserved.
 *  
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"), 
 * to deal in the Software without restriction, including without limitation 
 * the rights to use, copy, modify, merge, publish, distribute, sublicense, 
 * and/or sell copies of the Software, and to permit persons to whom the 
 * Software is furnished to do so, subject to the following conditions:
 *  
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *  
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER 
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING 
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER 
 * DEALINGS IN THE SOFTWARE.
 * 
 */

(function () {
    "use strict";

    // Dependencies
    // ------------
    
    var util = require("util"),
        EventEmitter = require("events").EventEmitter,
        fs = require("fs"),
        net = require("net"),
        stream = require("stream"),
        psCrypto = require("./ps_crypto");
    
    // Constants
    // ---------
        
    // Protocol constants
    var MESSAGE_HEADER_LENGTH     = 8,
        MESSAGE_LENGTH_OFFSET     = 0,
        MESSAGE_STATUS_OFFSET     = 4,
        MESSAGE_STATUS_LENGTH     = 4,

        PAYLOAD_HEADER_LENGTH     = 12,
        PAYLOAD_PROTOCOL_OFFSET   = 0,
        PAYLOAD_ID_OFFSET         = 4,
        PAYLOAD_TYPE_OFFSET       = 8,

        MAX_MESSAGE_ID            = 256 * 256 * 256,
        PROTOCOL_VERSION          = 1,
        MESSAGE_TYPE_ERROR        = 1,
        MESSAGE_TYPE_JAVASCRIPT   = 2,
        MESSAGE_TYPE_PIXMAP       = 3,
        STATUS_NO_COMM_ERROR      = 0;
        
    var RE_ONLY_DIGITS = /^[0-9]+$/;

    // OutgoingJavascriptMessage Class
    // ===============================

    // Constructor
    // -----------

    function OutgoingJavascriptMessage(jsString, id, derivedKey) {
        if (!(this instanceof OutgoingJavascriptMessage)) {
            return new OutgoingJavascriptMessage(jsString, id, derivedKey);
        } else {
            stream.Readable.call(this);

            var self = this;

            self._jsString = jsString;

            self._messageHeader = new Buffer(MESSAGE_HEADER_LENGTH);
            self._payloadHeader = new Buffer(PAYLOAD_HEADER_LENGTH);

            var payloadLength = PAYLOAD_HEADER_LENGTH + Buffer.byteLength(self._jsString, "utf8");
            if (derivedKey) {
                payloadLength = psCrypto.encryptedLength(payloadLength);
            }

            // message length includes status and payload, but not the UInt32 specifying message length
            var messageLength = payloadLength + MESSAGE_STATUS_LENGTH;
            self._messageHeader.writeUInt32BE(messageLength, MESSAGE_LENGTH_OFFSET);
            self._messageHeader.writeInt32BE(STATUS_NO_COMM_ERROR, MESSAGE_STATUS_OFFSET);

            self._payloadHeader.writeUInt32BE(PROTOCOL_VERSION, PAYLOAD_PROTOCOL_OFFSET);
            self._payloadHeader.writeUInt32BE(id, PAYLOAD_ID_OFFSET);
            self._payloadHeader.writeUInt32BE(MESSAGE_TYPE_JAVASCRIPT, PAYLOAD_TYPE_OFFSET);

            self._payloadBufferList = [];

            if (derivedKey) {
                self._payloadStream = psCrypto.createCipherStream(derivedKey);
            } else {
                self._payloadStream = new stream.PassThrough();
            }

            // do an initial _read call as soon as we have data available from the payload stream
            self._needsRead = true;

            self._payloadStream.on("readable", function () {
                var b;
                while (true) {
                    b = self._payloadStream.read();
                    if (b) {
                        self._payloadBufferList.push(b);
                    } else {
                        break;
                    }
                }
                if (self._needsRead) {
                    // If _needsRead flag is set, then the last time _read was called, we didn't have
                    // any data to send to the consumer. Now we do, so call _read again.
                    self._read();
                }
            });

            self._payloadStream.on("end", function () {
                self._payloadStreamDone = true;
                if (self._needsRead) {
                    // If _needsRead flag is set, then the last time _read was called, we didn't have
                    // any data to send to the consumer. Now we do, so call _read again.
                    self._read();
                }
            });

            self._payloadStream.on("drain", function () {
                self._doPayloadStreamWrite();
            });
            self._doPayloadStreamWrite();

        }
    }

    OutgoingJavascriptMessage.prototype = Object.create(
        stream.Readable.prototype,
        { constructor: { value: OutgoingJavascriptMessage }}
    );

    // Member Variables
    // ----------------

    OutgoingJavascriptMessage.prototype._jsString              = null;
    OutgoingJavascriptMessage.prototype._messageHeader         = null;
    OutgoingJavascriptMessage.prototype._messageHeaderSent     = false;
    OutgoingJavascriptMessage.prototype._payloadStream         = null;
    OutgoingJavascriptMessage.prototype._payloadStreamDone     = false;
    OutgoingJavascriptMessage.prototype._payloadBufferList     = null;
    OutgoingJavascriptMessage.prototype._payloadHeader         = null;
    OutgoingJavascriptMessage.prototype._payloadHeaderWritten  = false;
    OutgoingJavascriptMessage.prototype._payloadBodyWritten    = false;
    OutgoingJavascriptMessage.prototype._needsRead             = true;

    // Methods
    // -------

    OutgoingJavascriptMessage.prototype._read = function () {
        var self = this,
            pushMore = false;

        self._needsRead = false;

        while (true) {
            if (!self._messageHeaderSent) {
                self._messageHeaderSent = true;
                pushMore = self.push(self._messageHeader);
            } else {
                if (self._payloadBufferList.length > 0) {
                    pushMore = self.push(self._payloadBufferList.pop());
                } else if (self._payloadStreamDone) {
                    self.push(null);
                    pushMore = false;
                } else {
                    // No data available, so set a flag to call _read again when it is. Both "readable"
                    // and "end" event handlers for the payload stream call _read if this flag is set.
                    self._needsRead = true;
                    pushMore = false;
                }
            }

            if (!pushMore) {
                break;
            }
        }
    };

    OutgoingJavascriptMessage.prototype._doPayloadStreamWrite = function () {
        var writeMore = false;

        while (true) {
            if (!this._payloadHeaderWritten) {
                this._payloadHeaderWritten = true;
                writeMore = this._payloadStream.write(this._payloadHeader);
            } else if (!this._payloadWritten) {
                this._payloadWritten = true;
                writeMore = this._payloadStream.write(this._jsString, "utf8");
            } else { // end of data
                this._payloadStream.end();
                writeMore = false;
            }

            if (!writeMore) {
                break;
            }
        }
    };

    // Factory Functions
    // -----------------    
    
    function createOutgoingJavascriptMessage(jsString, id, derivedKey) {
        return new OutgoingJavascriptMessage(jsString, id, derivedKey);
    }


    // PhotoshopClient Class
    // =====================
    
    // Constructor
    // -----------
    
    function PhotoshopClient(options, connectListener) {
        var self = this;

        function setupStreamHandlers() {
            // This function does NOT set up error handlers, because we want slightly
            // different error handlers depending on whether we have sockets or pipes

            self._inputStream.on("readable", self._handleReadable.bind(self));
            self._readState = {
                readingHeader:         true,
                payloadBytesRemaining: 0,
                payloadStream:         null,
                payloadStreamWritable: false
            };

            self._pipeQueue = [];
            self._canPipe = true;

            self._outputStream.on("unpipe", function () {
                self._canPipe = true;
                self._pipeWhenFree();
            });
        }

        function connectPipes() {
            // If FDs are either numbers or strings that are actually positive integers, then 
            // they're file descriptors. Otherwise, they are named pipes.

            // Parse any FDs that are numbers as strings
            if (typeof options.inputFd === "string" && RE_ONLY_DIGITS.test(options.inputFd)) {
                options.inputFd = parseInt(options.inputFd, 10);
            }
            if (typeof options.outputFd === "string" && RE_ONLY_DIGITS.test(options.outputFd)) {
                options.outputFd = parseInt(options.outputFd, 10);
            }

            // Create read/write streams
            if (typeof options.inputFd === "number") {
                self._inputStream = fs.createReadStream(null, {fd: options.inputFd});
            } else {
                self._inputStream = fs.createReadStream(options.inputFd);
            }
            self._inputStream.on("error", function (err) {
                self.emit("error", "error on input stream: " + err);
            });

            if (typeof options.outputFd === "number") {
                self._outputStream = fs.createWriteStream(null, {fd: options.outputFd});
            } else {
                self._outputStream = fs.createWriteStream(options.outputFd);
            }
            self._outputStream.on("error", function (err) {
                self.emit("error", "error on output stream: " + err);
            });

            self._derivedKey = null; // no encryption on pipes

            setupStreamHandlers();

            // Creating pipe connections is synchronous, but sockets are async.
            // We want all code paths to be async.
            process.nextTick(function () { self.emit("connect"); });
        }
        
        function connectSockets() {
            var socket;

            function socketConnectErrorHandler(err) {
                self.emit("error", "error connecting socket: " + err);
            }

            function socketConnectHandler() {
                socket.removeListener("error", socketConnectErrorHandler);
                socket.on("error", function (err) {
                    self.emit("error", "error on socket: " + err);
                });

                self._inputStream = socket;
                self._outputStream = socket;

                setupStreamHandlers();

                self.emit("connect");
            }

            socket = new net.Socket();
            socket.connect(options.port, options.host);
            socket.once("error", socketConnectErrorHandler);
            socket.once("connect", socketConnectHandler);
    
            self._derivedKey = psCrypto.createDerivedKey(options.password);

        }

        if (!self instanceof PhotoshopClient) {
            return new PhotoshopClient(options, connectListener);
        } else {
            if (!options) {
                options = {};
            }

            if (connectListener) {
                self.once("connect", connectListener);
            }

            if (options.inputFd && options.outputFd) {
                connectPipes();
            } else if (options.host && options.port && options.password) {
                connectSockets();
            } else {
                self.emit("error", "must specify all necessary options for either pipe or socket connection");
            }
        }
    }
    util.inherits(PhotoshopClient, EventEmitter);

    // Member Variables
    // ----------------

    PhotoshopClient.prototype._inputStream = null;
    PhotoshopClient.prototype._outputStream = null;
    PhotoshopClient.prototype._derivedKey = null;
    PhotoshopClient.prototype._pipeQueue = null;
    PhotoshopClient.prototype._canPipe = false;
    PhotoshopClient.prototype._commandCount = 0;
    PhotoshopClient.prototype._readState = null;
    
    // Methods
    // -------

    PhotoshopClient.prototype._pipeWhenFree = function () {
        var self = this;

        if (self._canPipe && self._pipeQueue.length > 0) {
            var thePipe = self._pipeQueue.shift();
            thePipe.on("end", function () {
                thePipe.unpipe();
            });
            thePipe.pipe(this._outputStream, {end: false});
        }
    };

    PhotoshopClient.prototype._handleReadable = function () {
        var self = this,
            buffer,
            commStatus;

        // When calling "unshift", the new "readable" event may happen synchronously.
        // We want to finish our current processing before reading, so we need to
        // call unshift on nextTick.
        function unshiftNextTick(buffer) {
            process.nextTick(function () {
                self._inputStream.unshift(buffer);
            });
        }

        if (self._readState.readingHeader) {
            buffer = self._inputStream.read();

            if (buffer) {

                if (buffer.length < MESSAGE_HEADER_LENGTH) {
                    unshiftNextTick(buffer);
                } else { // read entire header
                    self._readState.readingHeader = false;

                    // We may have read more than the header, so push the rest back on.
                    if (buffer.length > MESSAGE_HEADER_LENGTH) {
                        unshiftNextTick(buffer.slice(MESSAGE_HEADER_LENGTH));
                    }

                    commStatus = buffer.readInt32BE(MESSAGE_STATUS_OFFSET);
                    if (commStatus !== STATUS_NO_COMM_ERROR) {
                        self.emit("error", "communications error: " + commStatus);
                    } else {
                        self._readState.payloadBytesRemaining =
                            buffer.readUInt32BE(MESSAGE_LENGTH_OFFSET) -
                            (MESSAGE_HEADER_LENGTH - MESSAGE_STATUS_OFFSET);

                        if (self._derivedKey) {
                            self._readState.payloadStream = psCrypto.createDecipherStream(self._derivedKey);
                        } else {
                            self._readState.payloadStream = new stream.PassThrough();
                        }
                        self._readState.payloadStreamWritable = true;
                        self._readState.payloadStream.on("drain", function () {
                            self._readState.payloadStreamWritable = true;
                        });

                        // BEGIN HACK

                        self._readState.payloadBuffer = new Buffer(self._readState.payloadBytesRemaining);
                        self._readState.payloadBufferPointer = 0;

                        self._readState.payloadStream.on("readable", function () {
                            var b = self._readState.payloadStream.read();
                            if (b) {
                                b.copy(self._readState.payloadBuffer, self._readState.payloadBufferPointer);
                                self._readState.payloadBufferPointer += b.length;
                            }
                        });

                        self._readState.payloadStream.on("end", function () {
                            self._readState.payloadBuffer =
                                self._readState.payloadBuffer.slice(0, self._readState.payloadBufferPointer);
                            console.log("done reading payload",
                                self._readState.payloadBuffer.length,
                                self._readState.payloadBuffer
                            );
                            if (self._readState.payloadBuffer.length > 0) {
                                self._processMessage(self._readState.payloadBuffer);
                            } else {
                                console.log("empty payload, throwing away");
                            }
                            self._readState.payloadBuffer = null;
                            self._readState.payloadBufferPointer = 0;
                        });

                        // END HACK

                    }
                }
            }
        } else { // reading payload
            if (!self._readState.payloadStreamWritable) {
                self._readState.payloadStream.once("drain", function () {
                    // try reading again on next tick, so that other drain handlers
                    // have a chance to set the payloadStreamWritable flag
                    process.nextTick(self._handleReadable().bind(self));
                });
            } else { // ready to write to payload stream, so okay to read
                buffer = self._inputStream.read();

                if (buffer) {
                    if (buffer.length > self._readState.payloadBytesRemaining) {
                        unshiftNextTick(buffer.slice(self._readState.payloadBytesRemaining));
                        buffer = buffer.slice(0, self._readState.payloadBytesRemaining);
                    }

                    self._readState.payloadStreamWritable = self._readState.payloadStream.write(buffer);

                    self._readState.payloadBytesRemaining -= buffer.length;
                    if (self._readState.payloadBytesRemaining < 1) {
                        self._readState.readingHeader = true;
                        self._readState.payloadStream.end();
                        self._readState.payloadStream = null;
                        self._readState.payloadStreamWritable = false;
                    }
                }
            }
        }
    };

    PhotoshopClient.prototype.sendCommand = function (javascript) {
        if (this._commandCount >= MAX_MESSAGE_ID) {
            this._commandCount = 0;
        }

        var id = ++this._commandCount;

        var command = new OutgoingJavascriptMessage(javascript, id, this._derivedKey);
        this._pipeQueue.push(command);
        this._pipeWhenFree();

        return id;
    };
    
    PhotoshopClient.prototype._processMessage = function (bodyBuffer) {
        if (bodyBuffer.length < PAYLOAD_HEADER_LENGTH) {
            console.log("payload buffer shorter than payload header!");
            return;
        }
        var protocolVersion = bodyBuffer.readUInt32BE(PAYLOAD_PROTOCOL_OFFSET),
            messageID = bodyBuffer.readUInt32BE(PAYLOAD_ID_OFFSET),
            messageType = bodyBuffer.readUInt32BE(PAYLOAD_TYPE_OFFSET),
            messageBody = bodyBuffer.slice(PAYLOAD_HEADER_LENGTH);
        
        var rawMessage = {
            protocolVersion: protocolVersion,
            id: messageID,
            type: messageType,
            body: messageBody
        };

        if (protocolVersion !== PROTOCOL_VERSION) {
            this.emit("error", "unknown protocol version", protocolVersion);
        }
        else if (messageType === MESSAGE_TYPE_JAVASCRIPT) {
            var messageBodyString = messageBody.toString("utf8");
            var messageBodyParts = messageBodyString.split("\r");
            var eventName = null;
            var parsedValue = null;
            
            if (messageBodyParts.length === 2) {
                eventName = messageBodyParts[0];
            }
            
            try {
                parsedValue = JSON.parse(messageBodyParts[messageBodyParts.length - 1]);
                console.log("got JS message: %j", parsedValue);
            } catch (jsonParseException) {
                // Many commands pass JSON back. However, some pass strings that result from
                // toStrings of un-JSON-ifiable data (e.g. "[ActionDescriptor]").
                // TODO: In the future, it might make more sense to have a different slot in
                // the message that gives parsed data (if available) and unparsed string (always)
                parsedValue = messageBodyParts[messageBodyParts.length - 1];
            }

            if (eventName) {
                this.emit("event", messageID, eventName, parsedValue, rawMessage);
            } else {
                this.emit("message", messageID, parsedValue, rawMessage);
            }
        } else if (messageType === MESSAGE_TYPE_PIXMAP) {
            this.emit("pixmap", messageID, messageBody, rawMessage);
        } else if (messageType === MESSAGE_TYPE_ERROR) {
            this.emit("error", { id: messageID, body: messageBody.toString("utf8") });
        } else {
            this.emit("communicationsError", "unknown message type", messageType);
        }
    };
        
    // Factory Functions
    // -----------------    
    
    function createClient(options, connectListener) {
        return new PhotoshopClient(options, connectListener);
    }

    // Public Interface
    // =================================

    exports.PhotoshopClient = PhotoshopClient;
    exports.createClient = createClient;

    exports._createOutgoingJavascriptMessage = createOutgoingJavascriptMessage; // for testing

}());
