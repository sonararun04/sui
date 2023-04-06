// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
import { useLayoutEffect, useState } from 'react';

export function useMediaQuery(query: string): boolean {
    const getMatches = (query: string): boolean => {
        // Prevents SSR issues
        if (typeof window !== 'undefined') {
            return window.matchMedia(query).matches;
        }
        return false;
    };

    const [matches, setMatches] = useState<boolean>(getMatches(query));

    useLayoutEffect(() => {
        const matchMedia = window.matchMedia(query);
        const listener = () => setMatches(getMatches(query));

        listener();

        matchMedia.addEventListener('change', listener);
        return () => {
            matchMedia.removeEventListener('change', listener);
        };
    }, [query]);

    return matches;
}
