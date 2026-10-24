export declare const THREADS: string[];
export declare const MEETINGS: string[];
export declare const RECURRING: string[];
export declare const LAST_TOUCH: string[];
export declare const NAMES: string[];
export declare function grade(input?: {
  threads?: string;
  meetings?: string;
  recurring?: string;
  lastTouch?: string;
  explicit?: boolean;
  sameOrg?: boolean;
  provenance?: 'observed' | 'imported' | 'self_reported';
}): number;
