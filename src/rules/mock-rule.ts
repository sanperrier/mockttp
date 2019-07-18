/**
 * @module MockRule
 */

import * as _ from 'lodash';
import uuid = require("uuid/v4");

import { deserialize, SerializationOptions } from '../util/serialization';
import { waitForCompletedRequest } from '../server/request-utils';

import { OngoingRequest, CompletedRequest, OngoingResponse } from "../types";
import {
  MockRule as MockRuleInterface,
  RuleCompletionChecker,
  RequestHandler,
  RequestMatcher,
  MockRuleData
} from "./mock-rule-types";

import * as matching from "./matchers";
import * as handling from "./handlers";
import * as completion from "./completion-checkers";

function validateMockRuleData(data: MockRuleData): void {
    if (!data.matchers || data.matchers.length === 0) {
        throw new Error('Cannot create a rule without at least one matcher');
    }
    if (!data.handler) {
        throw new Error('Cannot create a rule with no handler');
    }
}

export function serializeRuleData(data: MockRuleData, options?: SerializationOptions) {
    validateMockRuleData(data);

    return {
        matchers: data.matchers.map(m => m.serialize(options)),
        handler: data.handler.serialize(options),
        completionChecker: data.completionChecker && data.completionChecker.serialize(options)
    }
};

export function deserializeRuleData(data: MockRuleData, options?: SerializationOptions): MockRuleData {
    return {
        matchers: data.matchers.map((m) =>
            deserialize(m, matching.MatcherLookup, options)
        ),
        handler: deserialize(data.handler, handling.HandlerLookup, options),
        completionChecker: data.completionChecker && deserialize(
            data.completionChecker,
            completion.CompletionCheckerLookup,
            options
        )
    };
}

export class MockRule implements MockRuleInterface {
    private matchers: RequestMatcher[];
    private handler: RequestHandler;
    private completionChecker?: RuleCompletionChecker;

    public id: string = uuid();
    public requests: Promise<CompletedRequest>[] = [];

    constructor(data: MockRuleData) {
        validateMockRuleData(data);

        this.matchers = data.matchers;
        this.handler = data.handler;
        this.completionChecker = data.completionChecker;
    }

    matches(request: OngoingRequest) {
        return matching.matchesAll(request, this.matchers);
    }

    handle(request: OngoingRequest, response: OngoingResponse): Promise<void> {
        let completedAndRecordedPromise = (async () => {
            await this.handler.handle(request, response);
            return waitForCompletedRequest(request);
        })();

        // Requests are added to rule.requests as soon as they start being handled.
        this.requests.push(completedAndRecordedPromise);

        return completedAndRecordedPromise as Promise<any>;
    }

    isComplete(): boolean | null {
        if (this.completionChecker) {
            return this.completionChecker.isComplete(this.requests);
        } else {
            return null;
        }
    }

    explain(): string {
        let explanation = `Match requests ${matching.explainMatchers(this.matchers)}, ` +
        `and then ${this.handler.explain()}`;

        if (this.completionChecker) {
            explanation += `, ${this.completionChecker.explain(this.requests)}.`;
        } else {
            explanation += '.';
        }

        return explanation;
    }
}